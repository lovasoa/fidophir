// SPDX-License-Identifier: Apache-2.0
//! One typed blocking worker; no daemon RPC endpoint and no parallel CTAP commands.
use crate::{
    Error, Result,
    io::{SharedIo, boot_ms, dispatch_desktop},
    state::{PARENT, Store},
    tpm::{Blob, Kind, ParentRecord, Tpm},
};
use log::error;
use opensk::{
    api::{
        key_store::{self, CredentialSource, KeyStore},
        persist::{Persist, PersistCredentialIter, PersistIter, keys::CREDENTIALS},
    },
    ctap::{
        secret::Secret,
        status_code::{Ctap2StatusCode as Status, CtapResult},
    },
};
use std::{
    cell::RefCell,
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
    io: SharedIo,
    grant: RefCell<Option<Grant>>,
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
    pub fn new(root: PathBuf, io: SharedIo) -> Result<Self> {
        // The CI package uses a system-bus resource manager backed by swtpm.
        // Keep production transport fixed: runtime environment cannot select it.
        #[cfg(not(feature = "systemd-tests"))]
        let config = "device:/dev/tpmrm0";
        #[cfg(feature = "systemd-tests")]
        let config = "tabrmd:bus_name=com.intel.tss2.Tabrmd,bus_type=system";
        Self::start(root, config.parse()?, io)
    }

    #[cfg(any(test, feature = "integration-tests"))]
    pub fn for_test(root: PathBuf, config: &str, io: SharedIo) -> Result<Self> {
        if !config.starts_with("swtpm:host=127.0.0.1,port=") {
            return Err(Error::Invalid("test requires a loopback simulator"));
        }
        Self::start(root, config.parse()?, io)
    }

    fn start(root: PathBuf, config: TctiNameConf, io: SharedIo) -> Result<Self> {
        let (sender, receiver) = mpsc::sync_channel::<Task>(1);
        let (ready, initialized) = mpsc::sync_channel::<Result<()>>(1);
        let worker = std::thread::Builder::new()
            .name("fidophir-io".into())
            .spawn(move || {
                let startup = (|| {
                    let store = Store::open(&root)?;
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
        })))
    }

    fn run<T: Send + 'static>(
        &self,
        durable: bool,
        f: impl FnOnce(&mut Tpm, &Store) -> Result<T> + Send + 'static,
    ) -> CtapResult<T> {
        if self.0.io.borrow().cancelled() {
            return Err(Status::CTAP2_ERR_KEEPALIVE_CANCEL);
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
            dispatch_desktop();
            self.0
                .io
                .borrow_mut()
                .busy()
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
                            return Err(Status::CTAP2_ERR_PIN_AUTH_BLOCKED);
                        }
                        Err(error) if durable => fatal(error),
                        Err(error) => {
                            error!("operation failed: {error}");
                            self.clear();
                            return Err(Status::CTAP2_ERR_VENDOR_HARDWARE_FAILURE);
                        }
                    };
                    if !durable && self.0.io.borrow().cancelled() {
                        return Err(Status::CTAP2_ERR_KEEPALIVE_CANCEL);
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

    fn parent(&self) -> CtapResult<Option<ParentRecord>> {
        self.read_record(PARENT)?
            .map(|bytes| ParentRecord::decode(&bytes))
            .transpose()
            .map_err(|_| Status::CTAP2_ERR_VENDOR_INTERNAL_ERROR)
    }

    pub fn read_record(&self, key: usize) -> CtapResult<Option<Vec<u8>>> {
        self.run(false, move |_, store| store.read(key))
    }

    fn write_record(&self, key: usize, value: Vec<u8>) -> CtapResult<()> {
        self.run(true, move |_, store| store.write(key, &value))
    }

    fn hash(&self) -> CtapResult<Secret<[u8; 16]>> {
        self.0
            .grant
            .borrow()
            .as_ref()
            .map(|grant| grant.pin_hash.clone())
            .ok_or(Status::CTAP2_ERR_PUAT_REQUIRED)
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

    pub fn generate(&self) -> CtapResult<Blob> {
        let record = self.parent()?.ok_or(Status::CTAP2_ERR_PIN_NOT_SET)?;
        let hash = self.hash()?;
        self.run(false, move |tpm, _| tpm.generate(&record, &hash))
    }

    pub fn sign(&self, key: &Blob, message: &[u8]) -> CtapResult<p256::ecdsa::Signature> {
        let record = self.parent()?.ok_or(Status::CTAP2_ERR_PIN_NOT_SET)?;
        let hash = self.hash()?;
        let key = key.clone();
        let message = message.to_vec();
        self.run(false, move |tpm, _| {
            tpm.sign(&record, &hash, &key, &message)
        })
    }
}

impl Persist for Backend {
    fn find(&self, key: usize) -> CtapResult<Option<Vec<u8>>> {
        if key > 4095 {
            return Err(Status::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
        }
        self.read_record(key)
    }
    fn insert(&mut self, key: usize, bytes: &[u8]) -> CtapResult<()> {
        if key > 4095 {
            return Err(Status::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
        }
        self.write_record(key, bytes.to_vec())
    }
    fn remove(&mut self, key: usize) -> CtapResult<()> {
        if key > 4095 {
            return Err(Status::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
        }
        self.run(true, move |_, store| store.remove(key))
    }
    fn iter(&self) -> CtapResult<PersistIter<'_>> {
        let keys = self.run(false, |_, store| store.list())?;
        Ok(Box::new(keys.into_iter().filter(|k| *k <= 4095).map(Ok)))
    }
    fn iter_credentials(&self) -> CtapResult<PersistCredentialIter<'_>> {
        // OpenSK's count_credentials counts iterator errors as credentials.
        // Surface read and rename failures before returning the iterator instead.
        let credentials = self.run(false, |_, store| {
            let mut credentials = Vec::new();
            for key in store
                .list()?
                .into_iter()
                .filter(|k| CREDENTIALS.contains(k))
            {
                if let Some(value) = store.read(key)? {
                    credentials.push((key, value));
                }
            }
            Ok(credentials)
        })?;
        Ok(Box::new(credentials.into_iter().map(Ok)))
    }
    fn free_credential_key(&self) -> CtapResult<usize> {
        self.run(false, |_, store| store.free_credential_key())?
            .ok_or(Status::CTAP2_ERR_KEY_STORE_FULL)
    }
    fn reset(&mut self) -> CtapResult<()> {
        Err(Status::CTAP2_ERR_NOT_ALLOWED)
    }
    fn global_signature_counter(&self) -> CtapResult<u32> {
        Ok(0)
    }
}

impl KeyStore for Backend {
    fn init(&mut self) -> std::result::Result<(), key_store::Error> {
        Ok(())
    }
    fn reset(&mut self) -> std::result::Result<(), key_store::Error> {
        self.clear();
        Ok(())
    }
    fn wrap_credential(
        &mut self,
        credential: CredentialSource,
    ) -> std::result::Result<Vec<u8>, key_store::Error> {
        self.run(true, move |_, store| {
            store.create_non_discoverable(credential)
        })
        .map_err(|_| key_store::Error)
    }
    fn unwrap_credential(
        &mut self,
        bytes: &[u8],
        rp_id_hash: &[u8],
    ) -> std::result::Result<Option<CredentialSource>, key_store::Error> {
        let (Ok(id), Ok(rp_hash)) = (bytes.try_into(), rp_id_hash.try_into()) else {
            return Ok(None);
        };
        self.run(false, move |_, store| {
            store.read_non_discoverable(&id, &rp_hash)
        })
        .map_err(|_| key_store::Error)
    }
    fn cred_random(&mut self, uv: bool) -> std::result::Result<Secret<[u8; 32]>, key_store::Error> {
        let grant = self.0.grant.borrow();
        let Some(grant) = grant.as_ref() else {
            return Err(key_store::Error);
        };
        let mut key = Secret::<[u8; 32]>::default();
        let offset = if uv { 32 } else { 0 };
        key.copy_from_slice(&grant.master[offset..offset + 32]);
        Ok(key)
    }
    fn has_pin(&mut self) -> CtapResult<bool> {
        Ok(self.parent()?.is_some())
    }
    fn verify_pin_hash(&mut self, hash: &[u8; 16]) -> CtapResult<bool> {
        self.clear();
        let expires_at_ms = boot_ms().saturating_add(PIN_AUTHORIZATION_LIFETIME_MS);
        let record = self.parent()?.ok_or(Status::CTAP2_ERR_PIN_NOT_SET)?;
        let hash = Secret::from_exposed_secret(*hash);
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
            Err(Status::CTAP2_ERR_PIN_AUTH_BLOCKED) => {
                match self.run(false, |tpm, _| tpm.lockout_interval()) {
                    Ok(Some(seconds)) if seconds > 0 => log::warn!(
                        "TPM is temporarily locked; the configured recovery interval is {seconds} seconds per counter decrement, not an exact remaining wait; TPM resets may delay recovery; do not retry until it recovers; restarting Fidophir does not clear TPM lockout"
                    ),
                    _ => log::warn!(
                        "TPM is temporarily locked; recovery time is unavailable or requires special handling; do not retry until it recovers; restarting Fidophir does not clear TPM lockout"
                    ),
                }
                return Err(Status::CTAP2_ERR_PIN_AUTH_BLOCKED);
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

    fn store_pin(&mut self, hash: &[u8; 16], length: u8) -> CtapResult<()> {
        let new = Secret::from_exposed_secret(*hash);
        let record = if let Some(record) = self.parent()? {
            let old = self.hash()?;
            self.run(false, move |tpm, _| {
                tpm.change_pin(&record, &old, &new, length)
            })?
        } else {
            self.run(false, move |tpm, _| tpm.provision(&new, length))?
        };
        self.clear();
        self.write_record(
            PARENT,
            record
                .encode()
                .map_err(|_| Status::CTAP2_ERR_VENDOR_INTERNAL_ERROR)?,
        )?;
        Ok(())
    }
}

pub struct TpmEcdsa;
pub struct SigningKey(Blob);
pub struct VerifyingKey(p256::ecdsa::VerifyingKey);
pub struct Signature(p256::ecdsa::Signature);

impl opensk::api::crypto::ec_signing::Ecdsa for TpmEcdsa {
    type SecretKey = SigningKey;
    type PublicKey = VerifyingKey;
    type Signature = Signature;
}
impl opensk::api::crypto::ec_signing::EcSecretKey for SigningKey {
    type PublicKey = VerifyingKey;
    type Signature = Signature;
    fn random(
        _: &mut impl opensk::api::rng::Rng,
    ) -> std::result::Result<Self, opensk::api::crypto::ec_signing::Error> {
        crate::opensk_adapter::scope::current_backend()
            .generate()
            .map(Self)
            .map_err(|_| opensk::api::crypto::ec_signing::Error)
    }
    fn public_key(&self) -> VerifyingKey {
        VerifyingKey(
            self.0
                .verifying_key()
                .expect("validated Trusted Platform Module point"),
        )
    }
    fn sign(
        &self,
        message: &[u8],
    ) -> std::result::Result<Signature, opensk::api::crypto::ec_signing::Error> {
        crate::opensk_adapter::scope::current_backend()
            .sign(&self.0, message)
            .map(Signature)
            .map_err(|_| opensk::api::crypto::ec_signing::Error)
    }
    fn export(&self) -> Vec<u8> {
        self.0
            .encode()
            .expect("bounded Trusted Platform Module blob encoding")
    }
    fn import(bytes: &[u8]) -> Option<Self> {
        let blob = Blob::decode(bytes, Kind::Signing).ok()?;
        blob.verifying_key().ok()?;
        Some(Self(blob))
    }
}
impl opensk::api::crypto::ec_signing::EcPublicKey for VerifyingKey {
    type Signature = Signature;
    fn to_coordinates(&self, x: &mut [u8; 32], y: &mut [u8; 32]) {
        let point = self.0.to_sec1_point(false);
        x.copy_from_slice(point.x().expect("uncompressed point"));
        y.copy_from_slice(point.y().expect("uncompressed point"));
    }
}
impl opensk::api::crypto::ec_signing::EcSignature for Signature {
    fn to_der(&self) -> Vec<u8> {
        self.0.to_der().as_bytes().to_vec()
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
        }))
    }

    fn grant(expires_at_ms: u64) -> Grant {
        Grant {
            pin_hash: Secret::from_exposed_secret([0x42; 16]),
            master: Secret::from_exposed_secret([0x24; 64]),
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
