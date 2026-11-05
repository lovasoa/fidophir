// SPDX-License-Identifier: Apache-2.0
//! Journal stream logging. Only fixed operation names and sanitized errors belong here.
use opensk::ctap::{
    command::Command,
    data_formats::{ClientPinSubCommand, CredentialManagementSubCommand},
    status_code::Ctap2StatusCode as Status,
};
use std::{
    cell::Cell,
    fmt,
    io::Write,
    sync::atomic::{AtomicU64, Ordering},
    time::Instant,
};

thread_local! { static REQUEST: Cell<Option<u64>> = const { Cell::new(None) }; }
static NEXT: AtomicU64 = AtomicU64::new(1);

struct JournalLogger;

pub fn init() {
    static LOGGER: JournalLogger = JournalLogger;
    if log::set_logger(&LOGGER).is_ok() {
        log::set_max_level(log::LevelFilter::Info);
    }
}

impl log::Log for JournalLogger {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        // Dependencies may log protocol payloads; only accept our reviewed messages.
        metadata.level() <= log::Level::Info
            && (metadata.target() == "fidophir" || metadata.target().starts_with("fidophir::"))
    }
    fn log(&self, record: &log::Record<'_>) {
        if self.enabled(record.metadata()) {
            write(record.level(), *record.args());
        }
    }
    fn flush(&self) {}
}

fn write(level: log::Level, message: fmt::Arguments<'_>) {
    let priority = match level {
        log::Level::Error => 3,
        log::Level::Warn => 4,
        log::Level::Info => 6,
        log::Level::Debug | log::Level::Trace => 7,
    };
    // Ignore logging failures: a closed journal must not panic during key use.
    let mut stderr = std::io::stderr().lock();
    REQUEST.with(|request| {
        if let Some(id) = request.get() {
            let _ = writeln!(stderr, "<{priority}>fidophir: request={id} {message}");
        } else {
            let _ = writeln!(stderr, "<{priority}>fidophir: {message}");
        }
    });
}

pub struct Interaction {
    name: &'static str,
    start: Instant,
}
impl Interaction {
    pub fn begin(command: Option<&Command>) -> Self {
        let name = operation(command);
        REQUEST.with(|request| request.set(Some(NEXT.fetch_add(1, Ordering::Relaxed))));
        if let Some(name) = name {
            log::info!("{name}: started");
        }
        Self {
            name: name.unwrap_or("Security key request"),
            start: Instant::now(),
        }
    }
    pub(crate) fn finish(self, status: ResponseStatus, quiet: bool) {
        if !quiet || status != ResponseStatus::Known(Status::CTAP2_OK) {
            log::log!(
                status.level(),
                "{}: {}; status={} duration_ms={}",
                self.name,
                status.outcome(),
                status,
                self.start.elapsed().as_millis(),
            );
        }
    }
}
impl Drop for Interaction {
    fn drop(&mut self) {
        REQUEST.with(|request| request.set(None));
    }
}

pub fn operation(command: Option<&Command>) -> Option<&'static str> {
    use ClientPinSubCommand::*;
    use Command::*;
    match command {
        Some(AuthenticatorGetInfo) => None,
        Some(AuthenticatorClientPin(p)) => match p.sub_command {
            GetPinRetries | GetKeyAgreement | GetUvRetries => None,
            SetPin => Some("Set up security key PIN"),
            ChangePin => Some("Change security key PIN"),
            _ => Some("Verify security key PIN"),
        },
        Some(AuthenticatorMakeCredential(_)) => Some("Create passkey"),
        Some(AuthenticatorGetAssertion(_)) => Some("Sign with passkey"),
        Some(AuthenticatorGetNextAssertion) => Some("Sign with another passkey"),
        Some(AuthenticatorCredentialManagement(p)) => Some(match p.sub_command {
            CredentialManagementSubCommand::DeleteCredential => "Delete passkey",
            CredentialManagementSubCommand::UpdateUserInformation => {
                "Update passkey account details"
            }
            _ => "List saved passkeys",
        }),
        Some(AuthenticatorSelection) => Some("Select security key"),
        Some(AuthenticatorReset) => Some("Reset security key"),
        Some(_) => Some("Unsupported security key operation"),
        None => Some("Invalid security key request"),
    }
}

/// Decode once where OpenSK returns its serialized response. Unknown codes stay
/// intact for diagnosis; an empty response must never be reported as success.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ResponseStatus {
    Known(Status),
    Unknown(u8),
    Missing,
}

impl ResponseStatus {
    pub fn from_response(response: &[u8]) -> Self {
        let Some(&byte) = response.first() else {
            return Self::Missing;
        };
        // OpenSK exposes no byte-to-status conversion. Keep the conversion here,
        // and use named statuses for all logging decisions and explanations.
        const KNOWN: &[Status] = &[
            Status::CTAP2_OK,
            Status::CTAP1_ERR_INVALID_COMMAND,
            Status::CTAP1_ERR_INVALID_PARAMETER,
            Status::CTAP1_ERR_INVALID_LENGTH,
            Status::CTAP1_ERR_INVALID_SEQ,
            Status::CTAP1_ERR_TIMEOUT,
            Status::CTAP1_ERR_CHANNEL_BUSY,
            Status::CTAP1_ERR_LOCK_REQUIRED,
            Status::CTAP1_ERR_INVALID_CHANNEL,
            Status::CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
            Status::CTAP2_ERR_INVALID_CBOR,
            Status::CTAP2_ERR_MISSING_PARAMETER,
            Status::CTAP2_ERR_LIMIT_EXCEEDED,
            Status::CTAP2_ERR_FP_DATABASE_FULL,
            Status::CTAP2_ERR_LARGE_BLOB_STORAGE_FULL,
            Status::CTAP2_ERR_CREDENTIAL_EXCLUDED,
            Status::CTAP2_ERR_PROCESSING,
            Status::CTAP2_ERR_INVALID_CREDENTIAL,
            Status::CTAP2_ERR_USER_ACTION_PENDING,
            Status::CTAP2_ERR_OPERATION_PENDING,
            Status::CTAP2_ERR_NO_OPERATIONS,
            Status::CTAP2_ERR_UNSUPPORTED_ALGORITHM,
            Status::CTAP2_ERR_OPERATION_DENIED,
            Status::CTAP2_ERR_KEY_STORE_FULL,
            Status::CTAP2_ERR_NO_OPERATION_PENDING,
            Status::CTAP2_ERR_UNSUPPORTED_OPTION,
            Status::CTAP2_ERR_INVALID_OPTION,
            Status::CTAP2_ERR_KEEPALIVE_CANCEL,
            Status::CTAP2_ERR_NO_CREDENTIALS,
            Status::CTAP2_ERR_USER_ACTION_TIMEOUT,
            Status::CTAP2_ERR_NOT_ALLOWED,
            Status::CTAP2_ERR_PIN_INVALID,
            Status::CTAP2_ERR_PIN_BLOCKED,
            Status::CTAP2_ERR_PIN_AUTH_INVALID,
            Status::CTAP2_ERR_PIN_AUTH_BLOCKED,
            Status::CTAP2_ERR_PIN_NOT_SET,
            Status::CTAP2_ERR_PUAT_REQUIRED,
            Status::CTAP2_ERR_PIN_POLICY_VIOLATION,
            Status::CTAP2_ERR_PIN_TOKEN_EXPIRED,
            Status::CTAP2_ERR_REQUEST_TOO_LARGE,
            Status::CTAP2_ERR_ACTION_TIMEOUT,
            Status::CTAP2_ERR_UP_REQUIRED,
            Status::CTAP2_ERR_UV_BLOCKED,
            Status::CTAP2_ERR_INTEGRITY_FAILURE,
            Status::CTAP2_ERR_INVALID_SUBCOMMAND,
            Status::CTAP2_ERR_UV_INVALID,
            Status::CTAP2_ERR_UNAUTHORIZED_PERMISSION,
            Status::CTAP1_ERR_OTHER,
            Status::CTAP2_ERR_VENDOR_INTERNAL_ERROR,
            Status::CTAP2_ERR_VENDOR_HARDWARE_FAILURE,
        ];
        KNOWN
            .iter()
            .copied()
            .find(|status| *status as u8 == byte)
            .map(Self::Known)
            .unwrap_or(Self::Unknown(byte))
    }

    fn level(self) -> log::Level {
        use Status::*;
        match self {
            Self::Known(
                CTAP2_OK
                | CTAP2_ERR_OPERATION_DENIED
                | CTAP2_ERR_KEEPALIVE_CANCEL
                | CTAP2_ERR_USER_ACTION_TIMEOUT,
            ) => log::Level::Info,
            Self::Known(CTAP2_ERR_VENDOR_INTERNAL_ERROR | CTAP2_ERR_VENDOR_HARDWARE_FAILURE)
            | Self::Missing => log::Level::Error,
            _ => log::Level::Warn,
        }
    }

    fn outcome(self) -> &'static str {
        match self {
            Self::Known(status) => outcome(status),
            Self::Unknown(_) => {
                "unrecognized response status; start the browser operation again; if it repeats, report this status code, the application version and preceding journal errors after reviewing them for private information"
            }
            Self::Missing => {
                "internal failure: security key returned an empty response; retry the browser operation; if it repeats, check the service journal and report this operation and preceding errors"
            }
        }
    }
}

impl fmt::Display for ResponseStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Known(status) => write!(f, "0x{:02x}", *status as u8),
            Self::Unknown(byte) => write!(f, "0x{byte:02x}"),
            Self::Missing => f.write_str("missing"),
        }
    }
}

fn outcome(status: Status) -> &'static str {
    use Status::*;
    match status {
        CTAP2_OK => "completed",
        CTAP2_ERR_CREDENTIAL_EXCLUDED => {
            "a matching passkey already exists on this key; choose the website's sign-in option to use it, or add a different security key if you need another recovery method"
        }
        CTAP2_ERR_OPERATION_DENIED => {
            "approval was declined or unavailable; unlock your local desktop, make sure authentication prompts can appear, then start the browser operation again and approve the prompt; see the preceding desktop approval message for the reason"
        }
        CTAP2_ERR_KEY_STORE_FULL => {
            "no passkey slot is available (limit: 300); run `fido2-token -L -r /dev/fidophir-$(id -u)` to list websites, then follow README 'Manage your PIN and passkeys' to remove an unused passkey after confirming another sign-in method works"
        }
        CTAP2_ERR_KEEPALIVE_CANCEL => {
            "cancelled by the requesting application; if this was unintended, start the website's passkey operation again and keep its security key dialog open"
        }
        CTAP1_ERR_TIMEOUT | CTAP2_ERR_ACTION_TIMEOUT => {
            "the request did not finish in time; start the website's passkey operation again; if this repeats, check preceding desktop approval, storage and TPM errors"
        }
        CTAP2_ERR_USER_ACTION_TIMEOUT => {
            "approval did not finish in time; unlock your local desktop, check for a pending authentication prompt, then start the browser operation again and approve promptly"
        }
        CTAP2_ERR_NO_CREDENTIALS => {
            "this key has no usable passkey matching the request; check that you are using the same computer and desktop account where it was created; sign in with another method and add a passkey using the website's security settings, choosing 'security key'; check preceding storage warnings if a saved passkey was skipped"
        }
        CTAP2_ERR_PIN_INVALID => {
            "incorrect PIN; enter the Fidophir PIN you chose during setup, which is separate from your desktop login password; avoid repeated guesses because they can block both Fidophir and the TPM; if forgotten, use another sign-in method and follow README 'Reset a forgotten or blocked PIN' (deletes all local Fidophir passkeys)"
        }
        CTAP2_ERR_PIN_BLOCKED => {
            "PIN blocked after too many failed attempts; stop guessing and confirm another sign-in or recovery method works for your websites before following README 'Reset a forgotten or blocked PIN'; that reset deletes all local Fidophir passkeys, which must then be enrolled again; it does not clear a TPM lockout, which must be allowed to expire"
        }
        CTAP2_ERR_PIN_AUTH_INVALID => {
            "the request's PIN authorization is invalid or no longer available, for example after a failed request or service restart; cancel the browser's security key dialog, start the operation again and enter the Fidophir PIN when asked; if this repeats with the correct PIN, update the browser and check the service journal for earlier errors"
        }
        CTAP2_ERR_PIN_AUTH_BLOCKED => {
            "PIN attempts are temporarily blocked after repeated failures; stop guessing; once you know the correct Fidophir PIN, run `sudo systemctl restart \"fidophir@$(id -u).service\"` and start the browser operation again; restarting does not clear the remaining attempt limit or a TPM lockout; if the PIN is forgotten, follow README 'Reset a forgotten or blocked PIN' (deletes all local Fidophir passkeys)"
        }
        CTAP2_ERR_PIN_NOT_SET => {
            "no Fidophir PIN has been configured for this desktop account; install fido2-tools, run `fido2-token -S /dev/fidophir-$(id -u)`, choose a PIN of at least four characters and approve the desktop prompt; then retry enrollment and choose 'security key' in the browser"
        }
        CTAP2_ERR_PUAT_REQUIRED => {
            "this operation requires PIN verification; start the security key operation again and enter the Fidophir PIN when prompted; if you have not configured one, run `fido2-token -S /dev/fidophir-$(id -u)` first"
        }
        CTAP2_ERR_PIN_POLICY_VIOLATION => {
            "the proposed PIN does not meet the key's requirements; choose a PIN of at least four characters, enter it consistently in both confirmation fields and retry PIN setup or change"
        }
        CTAP2_ERR_PIN_TOKEN_EXPIRED => {
            "PIN authorization expired (it lasts at most 30 seconds); start the security key operation again and enter the Fidophir PIN when prompted"
        }
        CTAP1_ERR_INVALID_COMMAND | CTAP2_ERR_INVALID_SUBCOMMAND => {
            "the application requested a command this key does not support; for website enrollment choose 'security key' in the browser; for PIN or passkey management use the fido2-token commands in README; if this repeats, report the application version and this status code"
        }
        CTAP2_ERR_UNSUPPORTED_ALGORITHM => {
            "the requesting application asked for a signing algorithm this key does not support (Fidophir supports ES256); try another sign-in method or security key and report the incompatibility to the application or website"
        }
        CTAP2_ERR_UNSUPPORTED_OPTION | CTAP2_ERR_INVALID_OPTION => {
            "the application requested an unsupported option; Fidophir requires a saved passkey and PIN verification; retry from the website's passkey settings and choose 'security key'; if the website requires other options, use another authenticator"
        }
        CTAP2_ERR_NOT_ALLOWED => {
            "this operation is not allowed in the current key state; start the operation again using the README's PIN or passkey management commands; a browser or FIDO reset command cannot reset Fidophir: for a forgotten or blocked PIN, follow README 'Reset a forgotten or blocked PIN', which deletes all local Fidophir passkeys"
        }
        CTAP2_ERR_VENDOR_INTERNAL_ERROR | CTAP2_ERR_VENDOR_HARDWARE_FAILURE => {
            "an internal or TPM operation failed; check preceding errors for the cause; if the key disappears, wait for the service to restart automatically and retry once it returns; if failures continue, run `systemctl status \"fidophir@$(id -u).service\"`, check that /dev/tpmrm0 and /dev/uhid exist, and follow README troubleshooting; restore damaged state only from a matching backup as directed by its error message"
        }
        _ => {
            "the security key could not complete the request; cancel the security key dialog and start the website operation again; if it repeats, run `journalctl -u \"fidophir@$(id -u).service\" -b --no-pager` and report the operation, status code, browser version and relevant preceding errors after reviewing the logs for private information"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use log::Log;

    #[test]
    fn response_status_preserves_errors_and_rejects_missing_status() {
        let wrong_pin = ResponseStatus::from_response(&[Status::CTAP2_ERR_PIN_INVALID as u8]);
        assert_eq!(
            wrong_pin,
            ResponseStatus::Known(Status::CTAP2_ERR_PIN_INVALID)
        );
        assert!(wrong_pin.outcome().starts_with("incorrect PIN;"));
        assert_eq!(wrong_pin.level(), log::Level::Warn);
        let success = ResponseStatus::from_response(&[Status::CTAP2_OK as u8, 0xa0]);
        assert_eq!(success, ResponseStatus::Known(Status::CTAP2_OK));
        assert_eq!(success.level(), log::Level::Info);
        let missing = ResponseStatus::from_response(&[]);
        assert_eq!(missing, ResponseStatus::Missing);
        assert_eq!(missing.level(), log::Level::Error);
        assert_eq!(missing.to_string(), "missing");
        let unknown = ResponseStatus::from_response(&[0x99]);
        assert_eq!(unknown, ResponseStatus::Unknown(0x99));
        assert_eq!(unknown.to_string(), "0x99");
    }

    #[test]
    fn dependency_messages_are_excluded_from_the_journal() {
        let metadata = |target| {
            log::Metadata::builder()
                .level(log::Level::Info)
                .target(target)
                .build()
        };
        assert!(JournalLogger.enabled(&metadata("fidophir::approval")));
        assert!(JournalLogger.enabled(&metadata("fidophir")));
        assert!(!JournalLogger.enabled(&metadata("tss_esapi::context")));
        assert!(!JournalLogger.enabled(&metadata("fidophir_other")));
    }
}
