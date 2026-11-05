// SPDX-License-Identifier: Apache-2.0
//! Connects a fixed version of unmodified OpenSK to Fidophir's PIN checks.
//!
//! Fidophir presents a virtual security key to the browser. OpenSK implements
//! CTAP, the protocol the browser uses to talk to that key. Fidophir uses the
//! computer's Trusted Platform Module (TPM), a security chip, to protect the
//! passkey keys and check PINs. This module connects those two pieces.
//!
//! # The PIN verification trick
//!
//! When the user enters a PIN, the browser applies SHA-256, a repeatable
//! one-way calculation, and takes the first 16 bytes of the result. We call
//! these bytes the *candidate*. The browser encrypts the candidate before
//! sending it to OpenSK.
//!
//! OpenSK normally decrypts the candidate and compares it with an expected
//! value obtained from storage. Fidophir instead asks the TPM whether the
//! candidate is correct. Fidophir stores no expected PIN value on disk: it gives
//! OpenSK a fixed placeholder that only indicates that a PIN has been set.
//!
//! To get the candidate, Fidophir observes a key OpenSK already computes. The
//! browser and OpenSK agree on a temporary secret, then use HKDF, a standard
//! way to derive a key for a particular purpose, to make an AES encryption
//! key. Fidophir performs the same HKDF calculation OpenSK would use and copies
//! the resulting key while a PIN request is pending. It uses the key to decrypt
//! its copy of the request; OpenSK independently decrypts the same candidate.
//!
//! OpenSK asks Fidophir to decrypt the stored value. At that point Fidophir
//! checks the candidate with the TPM and translates its answer into a value
//! OpenSK can compare with its own copy of the candidate:
//!
//! - TPM accepts: return the candidate, so OpenSK's comparison succeeds.
//! - TPM rejects: flip one bit of the candidate, so the comparison must fail.
//!
//! Flipping a bit guarantees a mismatch even if an attacker chooses the
//! candidate. OpenSK still performs its own comparison and counts failed
//! attempts. Valid requests with incorrect PINs also reach the TPM's protection
//! against repeated guesses. The TPM checks the candidate as the value needed
//! to use a protected object. SHA-256 alone does not make a short PIN hard to
//! guess.
//!
//! # Compatibility and security contract
//!
//! These details depend on the OpenSK version in Cargo.toml:
//! - `ctap/pin_protocol.rs`: ClientPIN v2 derives its key with zero-salt HKDF
//!   and the label `CTAP2 AES key`; the derived key must never be modified.
//! - `ctap/client_pin.rs::verify_pin_hash_enc` records a failed attempt before
//!   calling `decrypt_pin_hash`, then compares values without revealing how
//!   many bytes matched. Fidophir checks the placeholder and recorded count.
//! - `check_and_store_new_pin` may read the accepted candidate again to check
//!   whether a replacement PIN is the same as the old one.
//! - After a successful PIN check, OpenSK issues a token for later commands and
//!   Fidophir keeps temporary TPM authorization, called a grant. Completion
//!   checks that the grant exists, or that PIN storage happened for SetPIN or
//!   ChangePIN. This catches success paths that skip the expected calls.
//! - `api/crypto/ec_signing.rs`: wrapped hardware keys are supported, but key
//!   generation/signing cannot return errors or receive an `Env`. A scoped
//!   backend selects the current Fidophir instance; hardware failures in those
//!   methods terminate the process safely.
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
//! authorization and may interrupt the browser request. Cancellation inside a
//! key operation that cannot return errors also stops the process; earlier
//! cancellation returns a normal CTAP error. There is no software signing
//! fallback.
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
                if let Some(encrypted_hash) = &parameters.pin_hash_enc {
                    env.backend.begin_pin_verification(encrypted_hash.clone())?;
                }
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
