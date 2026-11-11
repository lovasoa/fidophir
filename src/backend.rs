// SPDX-License-Identifier: Apache-2.0
//! One typed blocking worker; no daemon RPC endpoint and no parallel CTAP commands.
use crate::core::{BackendError, BackendResult, Secret};
use crate::{
    Error, Result,
    core::{HostServices, boot_ms},
    state::{PARENT, Store},
    tpm::{Blob, ParentRecord, Tpm},
};
use log::error;
use std::{
    cell::{Cell, RefCell},
    path::PathBuf,
    rc::Rc,
    sync::mpsc::{self, SyncSender},
    time::Duration,
};
use tss_esapi::{constants::response_code::Tss2ResponseCodeKind as RcKind, tcti_ldr::TctiNameConf};

type Task = Box<dyn FnOnce(&mut Tpm, &Store) + Send>;
/// Host policy, independent of OpenSK's token lifetime. Both must authorize a
/// protected command; a longer-lived upstream token cannot extend this lease.
pub const PIN_AUTHORIZATION_LIFETIME_MS: u64 = 30_000;

struct Grant {
    pin_hash: Secret<[u8; 16]>,
    master: Secret<[u8; 64]>,
    expires_at_ms: u64,
}

struct Inner {
    sender: Option<SyncSender<Task>>,
    worker: Option<std::thread::JoinHandle<()>>,
    io: Rc<dyn HostServices>,
    grant: RefCell<Option<Grant>>,
    tpm_lockout: Cell<bool>,
}
impl Drop for Inner {
    fn drop(&mut self) {
        self.grant.get_mut().take();
        self.sender.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[derive(Clone)]
pub struct Backend(Rc<Inner>);

fn fatal(message: impl std::fmt::Display) -> ! {
    error!("{message}");
    std::process::exit(1)
}

impl Backend {
    pub fn connect(
        root: PathBuf,
        config: TctiNameConf,
        io: Rc<dyn HostServices>,
        codec: &'static dyn crate::state::model::CredentialCodec,
    ) -> Result<Self> {
        let (sender, receiver) = mpsc::sync_channel::<Task>(1);
        let (ready, initialized) = mpsc::sync_channel::<Result<()>>(1);
        let worker = std::thread::Builder::new()
            .name("fidophir-io".into())
            .spawn(move || {
                let startup = (|| {
                    let store = Store::open(&root, codec)?;
                    Ok((Tpm::new(config)?, store))
                })();
                match startup {
                    Ok((mut tpm, store)) => {
                        if ready.send(Ok(())).is_err() {
                            return;
                        }
                        while let Ok(task) = receiver.recv() {
                            task(&mut tpm, &store);
                        }
                    }
                    Err(e) => {
                        let _ = ready.send(Err(e));
                    }
                }
            })?;
        initialized
            .recv_timeout(Duration::from_secs(10))
            .map_err(|_| Error::Invalid("worker initialization failed/timed out"))??;
        Ok(Self(Rc::new(Inner {
            sender: Some(sender),
            worker: Some(worker),
            io,
            grant: RefCell::new(None),
            tpm_lockout: Cell::new(false),
        })))
    }

    pub(crate) fn run<T: Send + 'static>(
        &self,
        durable: bool,
        f: impl FnOnce(&mut Tpm, &Store) -> Result<T> + Send + 'static,
    ) -> BackendResult<T> {
        if self.0.io.cancelled() {
            return Err(BackendError::Cancelled);
        }
        let (reply, result) = mpsc::sync_channel(1);
        self.0
            .sender
            .as_ref()
            .expect("live worker")
            .send(Box::new(move |tpm, store| {
                let _ = reply.send(f(tpm, store));
            }))
            .unwrap_or_else(|_| fatal("I/O worker stopped"));
        let deadline = boot_ms().saturating_add(10_000);
        loop {
            self.0
                .io
                .service()
                .unwrap_or_else(|_| fatal("UHID transport failed"));
            // Wake immediately on completion; the timeout only bounds how long
            // desktop dispatch, keepalives and cancellation can go unserviced.
            match result.recv_timeout(Duration::from_millis(5)) {
                Ok(answer) => {
                    let answer = match answer {
                        Ok(value) => value,
                        Err(Error::Tpm(tss_esapi::Error::Tss2Error(rc)))
                            if !durable && rc.kind() == Some(RcKind::Lockout) =>
                        {
                            return Err(BackendError::PinBlocked);
                        }
                        Err(error) if durable => fatal(error),
                        Err(error) => {
                            error!("operation failed: {error}");
                            self.clear();
                            return Err(BackendError::Hardware);
                        }
                    };
                    if !durable && self.0.io.cancelled() {
                        return Err(BackendError::Cancelled);
                    }
                    return Ok(answer);
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => fatal("I/O worker stopped"),
                Err(mpsc::RecvTimeoutError::Timeout) => (),
            }
            if boot_ms() >= deadline {
                fatal("I/O worker timed out");
            }
        }
    }

    pub(crate) fn parent(&self) -> BackendResult<Option<ParentRecord>> {
        self.read_record(PARENT)?
            .map(|bytes| ParentRecord::decode(&bytes))
            .transpose()
            .map_err(|_| BackendError::Internal)
    }

    pub fn read_record(&self, key: usize) -> BackendResult<Option<Vec<u8>>> {
        self.run(false, move |_, store| store.read(key))
    }

    pub(crate) fn write_record(&self, key: usize, value: Vec<u8>) -> BackendResult<()> {
        self.run(true, move |_, store| store.write(key, &value))
    }

    pub(crate) fn hash(&self) -> BackendResult<Secret<[u8; 16]>> {
        self.0
            .grant
            .borrow()
            .as_ref()
            .map(|grant| grant.pin_hash.clone())
            .ok_or(BackendError::AuthorizationRequired)
    }

    pub fn take_tpm_lockout(&self) -> bool {
        self.0.tpm_lockout.replace(false)
    }

    pub(crate) fn verify(&mut self, hash: &[u8; 16]) -> BackendResult<bool> {
        self.clear();
        let expires_at_ms = boot_ms().saturating_add(PIN_AUTHORIZATION_LIFETIME_MS);
        let record = self.parent()?.ok_or(BackendError::PinNotSet)?;
        let hash = Secret::new(*hash);
        let input = hash.clone();
        // Preserve wrong-authentication vs transport errors without turning an error into a grant.
        let answer = match self.run(false, move |tpm, _| match tpm.verify(&record, &input) {
            Ok(master) => Ok(Some(master)),
            Err(Error::Tpm(tss_esapi::Error::Tss2Error(rc)))
                if matches!(rc.kind(), Some(RcKind::AuthFail | RcKind::BadAuth)) =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        }) {
            Err(BackendError::PinBlocked) => {
                self.0.tpm_lockout.set(true);
                // The TPM definitively rejected the command before checking the PIN.
                // Restore only this durably charged attempt; uncertain failures stay charged.
                match self.run(false, |tpm, _| tpm.lockout_interval()) {
                    Ok(Some(seconds)) if seconds > 0 => log::warn!(
                        "TPM is temporarily locked; the configured recovery interval is {seconds} seconds per counter decrement, not an exact remaining wait; TPM resets may delay recovery; do not retry until it recovers; restarting Fidophir does not clear TPM lockout"
                    ),
                    _ => log::warn!(
                        "TPM is temporarily locked; recovery time is unavailable or requires special handling; do not retry until it recovers; restarting Fidophir does not clear TPM lockout"
                    ),
                }
                return Err(BackendError::PinBlocked);
            }
            result => result?,
        };
        if let Some(master) = answer {
            *self.0.grant.borrow_mut() = Some(Grant {
                pin_hash: hash,
                master,
                expires_at_ms,
            });
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn has_pin(&self) -> BackendResult<bool> {
        Ok(self.parent()?.is_some())
    }

    pub fn store_pin(&self, hash: &[u8; 16], length: u8) -> BackendResult<()> {
        let new = Secret::new(*hash);
        let record = if let Some(record) = self.parent()? {
            let old = self.hash()?;
            self.run(false, move |tpm, _| {
                tpm.change_pin(&record, &old, &new, length)
            })?
        } else {
            self.run(false, move |tpm, _| tpm.provision(&new, length))?
        };
        self.clear();
        self.write_record(PARENT, record.encode().map_err(|_| BackendError::Internal)?)
    }

    pub fn credential_random(&self, uv: bool) -> BackendResult<Secret<[u8; 32]>> {
        let grant = self.0.grant.borrow();
        let grant = grant.as_ref().ok_or(BackendError::AuthorizationRequired)?;
        let mut key = Secret::new([0; 32]);
        let offset = if uv { 32 } else { 0 };
        key.copy_from_slice(&grant.master[offset..offset + 32]);
        Ok(key)
    }

    pub fn matches_authorized_pin(&self, candidate: &[u8; 16]) -> Option<bool> {
        use p256::elliptic_curve::subtle::ConstantTimeEq;
        self.0
            .grant
            .borrow()
            .as_ref()
            .map(|grant| bool::from(grant.pin_hash.ct_eq(candidate)))
    }

    pub fn clear(&self) {
        self.0.grant.borrow_mut().take();
    }

    pub fn has_pin_authorization(&self) -> bool {
        self.0.grant.borrow().is_some()
    }

    /// Call between commands only. OpenSK admits a command using its entry-time
    /// token validity, including commands that wait for desktop approval.
    pub fn expire_pin_authorization(&self, now_ms: u64) {
        let mut grant = self.0.grant.borrow_mut();
        if grant
            .as_ref()
            .is_some_and(|grant| now_ms >= grant.expires_at_ms)
        {
            *grant = None;
        }
    }

    pub fn generate(&self) -> BackendResult<Blob> {
        let record = self.parent()?.ok_or(BackendError::PinNotSet)?;
        let hash = self.hash()?;
        self.run(false, move |tpm, _| tpm.generate(&record, &hash))
    }

    pub fn sign(&self, key: &Blob, message: &[u8]) -> BackendResult<p256::ecdsa::Signature> {
        let record = self.parent()?.ok_or(BackendError::PinNotSet)?;
        let hash = self.hash()?;
        let key = key.clone();
        let message = message.to_vec();
        self.run(false, move |tpm, _| {
            tpm.sign(&record, &hash, &key, &message)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // No worker or hardware: an accidental TPM/storage operation fails instead
    // of silently satisfying these tests through a mocked verification result.
    fn backend_without_worker() -> Backend {
        Backend(Rc::new(Inner {
            sender: None,
            worker: None,
            io: crate::io::Io::shared(),
            grant: RefCell::new(None),
            tpm_lockout: Cell::new(false),
        }))
    }

    fn grant(expires_at_ms: u64) -> Grant {
        Grant {
            pin_hash: Secret::new([0x42; 16]),
            master: Secret::new([0x24; 64]),
            expires_at_ms,
        }
    }

    #[test]
    fn pin_grant_expires_at_deadline() {
        let backend = backend_without_worker();
        *backend.0.grant.borrow_mut() = Some(grant(100));
        assert!(backend.has_pin_authorization());
        backend.expire_pin_authorization(99);
        assert!(backend.has_pin_authorization());
        backend.expire_pin_authorization(100);
        assert!(!backend.has_pin_authorization());
    }
}
