// SPDX-License-Identifier: Apache-2.0
//! Connects upstream OpenSK to Fidophir's TPM and PIN checks.
//!
//! Fidophir presents a virtual security key to the browser. OpenSK implements
//! CTAP, the protocol the browser uses to talk to that key. Fidophir uses the
//! computer's Trusted Platform Module (TPM), a security component, to protect the
//! passkey keys and check PINs. This module connects those two pieces.
//!
//! # Compatibility and security contract
//!
//! These details depend on the OpenSK commit locked in Cargo.lock:
//! - `ctap/client_pin.rs::verify_pin_hash_enc` decrypts the PIN candidate and
//!   deducts a retry before calling `KeyStore::verify_pin_hash`. Fidophir checks
//!   the configured-PIN marker and durable retry count, then asks the TPM to
//!   verify the candidate. OpenSK handles mismatches and resets retries on success.
//! - During a forced PIN change, `check_and_store_new_pin` calls verification
//!   again to reject reuse. Fidophir compares against this command's accepted
//!   candidate without another TPM attempt.
//! - After a successful PIN check, OpenSK issues a token for later commands and
//!   Fidophir keeps temporary TPM authorization, called a grant. Completion
//!   checks that the grant exists, or that PIN storage happened for SetPIN or
//!   ChangePIN. This catches success paths that skip the expected calls.
//! - `api/crypto/ec_signing.rs`: wrapped hardware keys are supported, but key
//!   generation/signing receive no `Env`. A scoped backend selects the current
//!   Fidophir instance; hardware failures return an error to OpenSK.
//!
//! All requests must pass through this module. Clearing our grant cannot revoke
//! OpenSK's token, so *every* protected command also needs the grant, including
//! metadata reads and deletes. OpenSK still checks message authentication codes
//! (MACs), permissions, the website a token is bound to, and command order. Our
//! grant expires at most 30 seconds after verification starts, independently of
//! the token's lifetime.
//!
//! When updating OpenSK, review these call sites and run the simulator contract
//! tests. Runtime checks enforce call order and successful completion; tests
//! also exercise rejection, permissions and expiry across whole requests.
//! Generic KeyStore errors deliberately hide the precise TPM status. They must
//! never become wrong-PIN success or a usable grant. Unexpected adapter states
//! terminate with diagnostics that contain no secrets; restart clears temporary
//! authorization and may interrupt the browser request. Cancellation returns a
//! normal CTAP error. There is no software signing fallback.
pub(crate) mod scope;

use crate::{env::LinuxEnv, io::boot_ms};
use opensk::{
    api::persist::Persist,
    ctap::{
        Channel, CtapState, check_user_presence,
        command::Command,
        data_formats::ClientPinSubCommand,
        hid::{CtapHid, CtapHidCommand, CtapHidError, HidPacket, HidPacketIterator, Message},
        status_code::{Ctap2StatusCode as Status, CtapResult},
    },
};

/// One serialized authenticator, shared by production and the integration runner.
/// OpenSK owns framing/channels; this boundary owns host authorization cleanup.
pub struct Authenticator {
    hid: CtapHid<LinuxEnv>,
    state: CtapState<LinuxEnv>,
}

impl Authenticator {
    pub fn new(env: &mut LinuxEnv) -> Self {
        let backend = env.backend.clone();
        Self {
            // No CTAP1 or WINK: this host has no physical indicator to blink.
            hid: CtapHid::new(
                CtapHid::<LinuxEnv>::CAPABILITY_CBOR | CtapHid::<LinuxEnv>::CAPABILITY_NMSG,
            ),
            state: scope::with_backend(&backend, || CtapState::new(env)),
        }
    }

    pub fn process_hid_packet(
        &mut self,
        env: &mut LinuxEnv,
        packet: &HidPacket,
    ) -> HidPacketIterator {
        env.backend.expire_pin_authorization(boot_ms());
        let Some(message) = self.hid.parse_packet(env, packet, false) else {
            return HidPacketIterator::none();
        };
        let response = match message.cmd {
            CtapHidCommand::Cbor => Message {
                payload: self.process_cbor(env, &message.payload, Channel::MainHid(message.cid)),
                ..message
            },
            CtapHidCommand::Msg | CtapHidCommand::Wink => {
                CtapHid::<LinuxEnv>::error_message(message.cid, CtapHidError::InvalidCmd)
            }
            // OpenSK has already handled INIT, PING, LOCK and transport errors.
            _ => message,
        };
        CtapHid::<LinuxEnv>::split_message(response)
    }

    fn process_cbor(&mut self, env: &mut LinuxEnv, bytes: &[u8], channel: Channel) -> Vec<u8> {
        let backend = env.backend.clone();
        scope::with_backend(&backend, || {
            env.set_approval_context(None, None);
            env.backend.take_tpm_lockout();
            let command = Command::deserialize(bytes);
            let quiet = command
                .as_ref()
                .is_ok_and(|c| crate::logging::operation(Some(c)).is_none());
            let interaction = crate::logging::Interaction::begin(command.as_ref().ok());
            let silent_lookup = command.as_ref().is_ok_and(|command| {
                matches!(command, Command::AuthenticatorGetAssertion(parameters) if !parameters.options.up)
            });
            let prepared = command.and_then(|command| prepare_command(env, &command, channel));
            let mut response = match &prepared {
                Ok(_) => self.state.process_command(env, bytes, channel),
                Err(status) => vec![*status as u8],
            };
            if env.backend.take_tpm_lockout() {
                response = vec![Status::CTAP2_ERR_PIN_AUTH_BLOCKED as u8];
            }
            if env.command_was_cancelled() {
                response = vec![Status::CTAP2_ERR_KEEPALIVE_CANCEL as u8];
            }
            finish_command(env, prepared.ok(), &response, silent_lookup);
            interaction.finish(
                crate::logging::ResponseStatus::from_response(&response),
                quiet,
            );
            response
        })
    }
}

/// Postconditions and authorization cleanup for successful commands.
/// Keep this local to the synchronous request; it is not another token state.
#[derive(Clone, Copy)]
enum AuthorizationOnSuccess {
    Preserve,
    RetainNewPinGrant,
    RequirePinStored,
}

fn prepare_command(
    env: &mut LinuxEnv,
    command: &Command,
    channel: Channel,
) -> CtapResult<AuthorizationOnSuccess> {
    use AuthorizationOnSuccess::*;
    use ClientPinSubCommand::*;
    match command {
        Command::AuthenticatorGetInfo | Command::AuthenticatorSelection => {
            if matches!(command, Command::AuthenticatorSelection) {
                env.set_approval_context(Some("use your security key"), None);
            }
            Ok(Preserve)
        }
        Command::AuthenticatorClientPin(parameters) => match parameters.sub_command {
            SetPin => {
                env.backend.clear();
                env.set_approval_context(Some("set up your security key PIN"), None);
                if env.backend.pin_hash()?.is_none() {
                    // Upstream has no initial-setup presence check. Reuse its
                    // public helper, including keepalives and cancellation.
                    check_user_presence(env, channel)?;
                }
                Ok(RequirePinStored)
            }
            ChangePin | GetPinToken | GetPinUvAuthTokenUsingPinWithPermissions => {
                // Never let an earlier grant stand in for this candidate.
                env.backend.clear();
                env.backend.begin_pin_verification()?;
                if parameters.sub_command == ChangePin {
                    env.set_approval_context(Some("change your security key PIN"), None);
                    Ok(RequirePinStored)
                } else {
                    Ok(RetainNewPinGrant)
                }
            }
            // Upstream rejects unsupported built-in UV; harmless queries need
            // no lease. An error still clears authorization at completion.
            GetPinRetries
            | GetKeyAgreement
            | GetUvRetries
            | GetPinUvAuthTokenUsingUvWithPermissions => Ok(Preserve),
        },
        Command::AuthenticatorReset => Err(Status::CTAP2_ERR_NOT_ALLOWED),
        protected => {
            // Default-deny applies to new commands too, particularly credential
            // management and continuation commands that may never touch TPM.
            if !env.backend.has_pin_authorization() {
                return Err(Status::CTAP2_ERR_PIN_AUTH_INVALID);
            }
            match protected {
                Command::AuthenticatorMakeCredential(parameters) => {
                    env.set_approval_context(Some("create a passkey"), Some(&parameters.rp.rp_id))
                }
                Command::AuthenticatorGetAssertion(parameters) => {
                    env.set_approval_context(Some("sign in"), Some(&parameters.rp_id))
                }
                _ => (),
            }
            Ok(Preserve)
        }
    }
}

fn finish_command(
    env: &mut LinuxEnv,
    prepared: Option<AuthorizationOnSuccess>,
    response: &[u8],
    silent_lookup: bool,
) {
    // Browsers probe excluded credentials silently before creating one using
    // the same PIN token. A miss is an expected result, not a failed grant.
    if silent_lookup
        && prepared.is_some()
        && response.first() == Some(&(Status::CTAP2_ERR_NO_CREDENTIALS as u8))
    {
        env.backend.expire_pin_authorization(boot_ms());
        return;
    }
    if response.first() != Some(&(Status::CTAP2_OK as u8)) {
        env.backend.clear();
        return;
    }
    match prepared {
        Some(AuthorizationOnSuccess::RetainNewPinGrant) => {
            // A TPM grant is provisional inside ClientPIN. Only successful
            // token issuance permits the following command to use it.
            env.backend.assert_pin_was_verified();
        }
        Some(AuthorizationOnSuccess::Preserve) => (),
        Some(AuthorizationOnSuccess::RequirePinStored) => {
            env.backend.assert_pin_was_stored();
            env.backend.clear();
        }
        None => env.backend.clear(),
    }
    // Match OpenSK's command-entry timeout semantics: an admitted command may
    // finish a long desktop prompt, then its expired authorization is erased.
    env.backend.expire_pin_authorization(boot_ms());
}
