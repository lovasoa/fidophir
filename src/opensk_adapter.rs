// SPDX-License-Identifier: Apache-2.0
//! Compatibility with **unmodified**, pinned OpenSK. Read before updating it.
//!
//! OpenSK normally decrypts a stored PIN verifier, then compares it with the
//! browser's candidate. We store no software verifier: the TPM checks the PIN.
//! The transparent HKDF adapter observes the genuine ClientPIN v2 AES key. Our
//! key-store callback decrypts the *same request*, asks the TPM, and returns the
//! candidate on acceptance or a guaranteed mismatch on rejection. OpenSK's own
//! comparison and wrong-PIN/lockout handling remain intact.
//!
//! Contract with vendor/OpenSK/libraries/opensk/src:
//! - `ctap/pin_protocol.rs`: ClientPIN v2 derives its key with zero-salt HKDF
//!   and the label `CTAP2 AES key`; crypto outputs must never be modified.
//! - `ctap/client_pin.rs::verify_pin_hash_enc`: durable retry charging precedes
//!   `decrypt_pin_hash`, followed by an independent constant-time comparison.
//!   The callback checks both the configured-PIN marker and charged counter.
//! - `check_and_store_new_pin` may read that hash again for the same-PIN policy.
//! - `ctap/token_state.rs`: USB tokens have a fixed, nonrolling 30-second limit.
//!   Our hardware lease starts earlier, before TPM verification.
//! - `api/crypto/ec_signing.rs`: wrapped hardware keys are supported, but key
//!   generation/signing cannot return errors or receive an Env. A scoped backend
//!   supplies the instance; hardware failures in those methods terminate safely.
//!
//! All requests must pass through this module. Clearing our grant cannot revoke
//! OpenSK's private token, so *every* protected command also needs a host lease,
//! including metadata reads/deletes. OpenSK still checks MACs, permissions, RP
//! binding and command sequencing; possession of our grant never replaces them.
//!
//! On an OpenSK update, review these call sites and run the simulator contract
//! tests: source equality alone cannot establish compatible callback semantics.
//! Generic KeyStore errors deliberately lose the precise TPM status. They must
//! never become wrong-PIN success or a usable grant. Unexpected adapter states
//! terminate with secret-free diagnostics; restart loses authorization and may
//! interrupt the browser request. Cancellation observed inside an infallible
//! key operation follows this same fail-stop path; earlier cancellation returns
//! a normal CTAP error. No software signing fallback is permitted.
pub(crate) mod scope;
pub use scope::PinProtocolHkdf256;

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
            let prepared = Command::deserialize(bytes)
                .and_then(|command| prepare_command(env, &command, channel));
            let mut response = match &prepared {
                Ok(_) => self.state.process_command(env, bytes, channel),
                Err(status) => vec![*status as u8],
            };
            if env.command_was_cancelled() {
                response = vec![Status::CTAP2_ERR_KEEPALIVE_CANCEL as u8];
            }
            finish_command(env, prepared.ok(), &response);
            response
        })
    }
}

/// What successful completion permits us to retain, not OpenSK permissions.
/// Keep this local to the synchronous request; it is not another token state.
#[derive(Clone, Copy)]
enum AuthorizationOnSuccess {
    Preserve,
    RetainNewPinGrant,
    Clear,
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
                Ok(Clear)
            }
            ChangePin | GetPinToken | GetPinUvAuthTokenUsingPinWithPermissions => {
                // Never let an earlier grant stand in for this candidate.
                env.backend.clear();
                if let Some(encrypted_hash) = &parameters.pin_hash_enc {
                    env.backend.begin_pin_verification(encrypted_hash.clone())?;
                }
                if parameters.sub_command == ChangePin {
                    env.set_approval_context(Some("change your security key PIN"), None);
                    Ok(Clear)
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
        Command::AuthenticatorMakeCredential(parameters) if !parameters.options.rk => {
            Err(Status::CTAP2_ERR_UNSUPPORTED_OPTION)
        }
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

fn finish_command(env: &mut LinuxEnv, prepared: Option<AuthorizationOnSuccess>, response: &[u8]) {
    if response.first() != Some(&(Status::CTAP2_OK as u8)) {
        env.backend.clear();
        return;
    }
    match prepared {
        Some(AuthorizationOnSuccess::RetainNewPinGrant) => {
            // A TPM grant is provisional inside ClientPIN. Only successful
            // token issuance permits the following command to use it.
            if !env.backend.has_pin_authorization() {
                crate::backend::adapter_invariant("token-issuance", "missing-tpm-authorization");
            }
        }
        Some(AuthorizationOnSuccess::Preserve) => (),
        Some(AuthorizationOnSuccess::Clear) | None => env.backend.clear(),
    }
    // Match OpenSK's command-entry timeout semantics: an admitted command may
    // finish a long desktop prompt, then its expired authorization is erased.
    env.backend.expire_pin_authorization(boot_ms());
}
