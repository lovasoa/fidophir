// SPDX-License-Identifier: Apache-2.0
//! Journal stream logging. Only fixed operation names and sanitized errors belong here.
use opensk::ctap::{
    command::Command,
    data_formats::{ClientPinSubCommand, CredentialManagementSubCommand},
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
    pub fn finish(self, status: u8, quiet: bool) {
        if !quiet || status != 0 {
            let level = if status == 0 || matches!(status, 0x27 | 0x2d | 0x2f) {
                log::Level::Info
            } else {
                log::Level::Warn
            };
            log::log!(
                level,
                "{}: {}; status=0x{status:02x} duration_ms={}",
                self.name,
                outcome(status),
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

fn outcome(status: u8) -> &'static str {
    match status {
        0 => "completed",
        0x19 => "a matching passkey already exists",
        0x27 => "approval was declined or unavailable",
        0x28 => "passkey storage is full; remove an unused passkey",
        0x2d => "cancelled by the requesting application",
        0x05 | 0x2f | 0x3a => "timed out waiting for completion",
        0x2e => "no matching passkey found",
        0x31 => "incorrect PIN",
        0x32 => "PIN blocked; stop retrying and check recovery options",
        0x33 => "PIN authorization is invalid or expired; enter the PIN again",
        0x34 => "PIN attempts temporarily blocked; restart the service before retrying",
        0x35 => "security key PIN has not been set up",
        0x36 => "PIN verification is required",
        0x37 => "PIN does not meet requirements",
        0x38 => "PIN authorization expired; enter the PIN again",
        0x01 | 0x26 | 0x2b | 0x30 | 0x3e => {
            "requested operation or option is not supported or allowed"
        }
        0xf2 | 0xf3 => "internal or hardware failure; check preceding errors",
        _ => "request failed; use the status code for diagnosis",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use log::Log;

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
