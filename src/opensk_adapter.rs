// SPDX-License-Identifier: Apache-2.0
//! Connects OpenSK's CTAP implementation to the TPM backend.
//!
//! OpenSK handles PIN policy, encrypted requests, token permissions and retries.
//! `Backend` verifies candidates and stores PINs through the KeyStore API.
//! Authorization is cleared before PIN attempts, after PIN storage, and on errors.
//!
//! Every protected command also needs Fidophir's short-lived TPM grant, including
//! metadata operations that never touch the TPM. Clearing that grant cannot
//! revoke OpenSK's token, so this check must cover all protected commands.
//! A silent credential lookup with no match preserves the grant for registration.
//!
//! Crypto methods without an `Env` parameter use `scope` to select the current
//! backend. The request boundary owns this scope and prevents nested dispatch.
pub(crate) mod scope;

use crate::{env::LinuxEnv, io::boot_ms};
use opensk::{
    api::key_store::KeyStore,
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
            let command = Command::deserialize(bytes);
            let quiet = command
                .as_ref()
                .is_ok_and(|c| crate::logging::operation(Some(c)).is_none());
            let interaction = crate::logging::Interaction::begin(command.as_ref().ok());
            let silent_lookup = command.as_ref().is_ok_and(|command| {
                matches!(command, Command::AuthenticatorGetAssertion(parameters) if !parameters.options.up)
            });
            let prepared = command.and_then(|command| prepare_command(env, &command, channel));
            let mut response = match prepared {
                Ok(()) => self.state.process_command(env, bytes, channel),
                Err(status) => vec![status as u8],
            };
            if env.command_was_cancelled() {
                response = vec![Status::CTAP2_ERR_KEEPALIVE_CANCEL as u8];
            }
            finish_command(env, &response, silent_lookup);
            interaction.finish(
                crate::logging::ResponseStatus::from_response(&response),
                quiet,
            );
            response
        })
    }
}

fn prepare_command(env: &mut LinuxEnv, command: &Command, channel: Channel) -> CtapResult<()> {
    use ClientPinSubCommand::*;
    match command {
        Command::AuthenticatorGetInfo | Command::AuthenticatorSelection => {
            if matches!(command, Command::AuthenticatorSelection) {
                env.set_approval_context(Some("use your security key"), None);
            }
            Ok(())
        }
        Command::AuthenticatorClientPin(parameters) => match parameters.sub_command {
            SetPin => {
                env.backend.clear();
                env.set_approval_context(Some("set up your security key PIN"), None);
                if !env.backend.has_pin()? {
                    // Upstream has no initial-setup presence check. Reuse its
                    // public helper, including keepalives and cancellation.
                    check_user_presence(env, channel)?;
                }
                Ok(())
            }
            ChangePin | GetPinToken | GetPinUvAuthTokenUsingPinWithPermissions => {
                // Never let an earlier grant stand in for this candidate.
                env.backend.clear();
                if parameters.sub_command == ChangePin {
                    env.set_approval_context(Some("change your security key PIN"), None);
                }
                Ok(())
            }
            // Upstream rejects unsupported built-in UV; harmless queries need
            // no lease. An error still clears authorization at completion.
            GetPinRetries
            | GetKeyAgreement
            | GetUvRetries
            | GetPinUvAuthTokenUsingUvWithPermissions => Ok(()),
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
            Ok(())
        }
    }
}

fn finish_command(env: &mut LinuxEnv, response: &[u8], silent_lookup: bool) {
    // Browsers reuse the PIN token after a silent excluded-credential miss.
    let status = response.first().copied();
    if status != Some(Status::CTAP2_OK as u8)
        && !(silent_lookup && status == Some(Status::CTAP2_ERR_NO_CREDENTIALS as u8))
    {
        env.backend.clear();
    }
    // An admitted command may finish a long prompt before its grant is erased.
    env.backend.expire_pin_authorization(boot_ms());
}
