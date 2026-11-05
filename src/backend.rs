// SPDX-License-Identifier: Apache-2.0
//! One typed blocking worker; no daemon RPC endpoint and no parallel CTAP commands.
use crate::{
    Error, Result,
    io::{SharedIo, boot_ms, dispatch_desktop},
    state::{PARENT, Store},
    tpm::{Blob, Kind, ParentRecord, Tpm},
};
use opensk::{
    api::{
        crypto::{aes256::Aes256, rust_crypto::SoftwareAes256},
        key_store::{self, CredentialSource, KeyStore},
        persist::{Persist, PersistCredentialIter, PersistIter, keys::CREDENTIALS},
    },
    ctap::{
        crypto_wrapper::aes256_cbc_decrypt,
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
/// `Persist::pin_hash` reports configuration, never a stored verifier.
pub(crate) const CONFIGURED_PIN_MARKER: [u8; 16] = [0; 16];

/// Host policy, independent of OpenSK's token lifetime. Both must authorize a
/// protected command; a longer-lived upstream token cannot extend this lease.
pub const PIN_AUTHORIZATION_LIFETIME_MS: u64 = 30_000;

struct Grant {
    pin_hash: Secret<[u8; 16]>,
    master: Secret<[u8; 64]>,
    expires_at_ms: u64,
}

/// Pending verification and earlier authorization are mutually exclusive.
/// `Granted` permits TPM work, not bypassing OpenSK's token/permission checks.
#[derive(Default)]
enum PinAccess {
    #[default]
    None,
    AwaitingKey(PinAttempt),
    ReadyToVerify {
        attempt: PinAttempt,
        aes_key: Secret<[u8; 32]>,
    },
    Granted(Grant),
    /// Completion witness only: PIN storage succeeded, and no grant survives it.
    PinStored,
}
struct PinAttempt {
    encrypted_hash: Vec<u8>,
    /// Persisted counter value required before this attempt may reach the TPM.
    expected_failure_count: u8,
}

impl PinAttempt {
    fn assert_retry_was_charged(&self, actual_failure_count: u8) {
        if actual_failure_count != self.expected_failure_count {
            adapter_invariant("pin-verification", "retry-not-durably-charged");
        }
    }
}

impl PinAccess {
    fn phase(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::AwaitingKey(_) => "awaiting-key",
            Self::ReadyToVerify { .. } => "ready-to-verify",
            Self::Granted(_) => "granted",
            Self::PinStored => "pin-stored",
        }
    }
}

/// Makes the unusual KeyStore return semantics explicit at the conversion site.
/// Rejection returns a value unequal to this exact candidate, never a constant
/// that an attacker could choose as their candidate.
enum TpmPinComparison {
    Accepted(Secret<[u8; 16]>),
    Rejected(Secret<[u8; 16]>),
    MalformedCandidate,
}
impl TpmPinComparison {
    fn into_opensk_expected_hash(self) -> Secret<[u8; 16]> {
        match self {
            Self::Accepted(hash) => hash,
            Self::Rejected(mut hash) => {
                hash[0] ^= 1;
                hash
            }
            // Upstream cannot decrypt this request to a 16-byte candidate, so
            // no returned 16-byte value can make its comparison succeed.
            Self::MalformedCandidate => Secret::default(),
        }
    }
}
struct Inner {
    sender: Option<SyncSender<Task>>,
    worker: Option<std::thread::JoinHandle<()>>,
    io: SharedIo,
    pin_access: RefCell<PinAccess>,
}
impl Drop for Inner {
    fn drop(&mut self) {
        *self.pin_access.get_mut() = PinAccess::None;
        self.sender.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[derive(Clone)]
pub struct Backend(Rc<Inner>);

/// Only static diagnostics: never format requests, hashes, keys, or enum payloads.
/// Release builds abort on panic; unit tests can check the same guard directly.
#[track_caller]
pub(crate) fn adapter_invariant(stage: &'static str, reason: &'static str) -> ! {
    panic!(
        "fidophir: fatal stage={stage} reason={reason} source={}",
        std::panic::Location::caller()
    )
}

#[track_caller]
fn fatal_crypto(stage: &'static str, status: Status) -> ! {
    eprintln!(
        "fidophir: fatal stage={stage} status={} source={}",
        status as u8,
        std::panic::Location::caller()
    );
    std::process::exit(1)
}

fn fatal(message: impl std::fmt::Display) -> ! {
    eprintln!("fidophir: {message}");
    std::process::exit(1)
}

impl Backend {
    pub fn new(root: PathBuf, io: SharedIo) -> Result<Self> {
        Self::start(root, "device:/dev/tpmrm0".parse()?, io)
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
            pin_access: RefCell::new(PinAccess::None),
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
                            eprintln!("fidophir: operation failed: {error}");
                            *self.0.pin_access.borrow_mut() = PinAccess::None;
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

    fn parent(&self) -> CtapResult<ParentRecord> {
        let bytes = self
            .read_record(PARENT)?
            .ok_or(Status::CTAP2_ERR_PIN_NOT_SET)?;
        ParentRecord::decode(&bytes).map_err(|_| Status::CTAP2_ERR_VENDOR_INTERNAL_ERROR)
    }

    pub fn read_record(&self, key: usize) -> CtapResult<Option<Vec<u8>>> {
        self.run(false, move |_, store| store.read(key))
    }

    fn write_record(&self, key: usize, value: Vec<u8>) -> CtapResult<()> {
        self.run(true, move |_, store| store.write(key, &value))
    }

    fn hash(&self) -> CtapResult<Secret<[u8; 16]>> {
        match &*self.0.pin_access.borrow() {
            PinAccess::Granted(grant) => Ok(grant.pin_hash.clone()),
            _ => Err(Status::CTAP2_ERR_PUAT_REQUIRED),
        }
    }

    /// Starting an attempt always revokes older hardware authorization.
    pub fn begin_pin_verification(&mut self, encrypted_hash: Vec<u8>) -> CtapResult<()> {
        self.clear();
        let expected_failure_count = self.pin_fails()?.saturating_add(1);
        *self.0.pin_access.borrow_mut() = PinAccess::AwaitingKey(PinAttempt {
            encrypted_hash,
            expected_failure_count,
        });
        Ok(())
    }

    pub(crate) fn observe_pin_aes_key(&self, key: &[u8; 32]) {
        let mut access = self.0.pin_access.borrow_mut();
        if matches!(&*access, PinAccess::AwaitingKey(_)) {
            let PinAccess::AwaitingKey(attempt) = std::mem::take(&mut *access) else {
                unreachable!();
            };
            *access = PinAccess::ReadyToVerify {
                attempt,
                aes_key: Secret::from_exposed_secret(*key),
            };
        } else if matches!(&*access, PinAccess::ReadyToVerify { .. }) {
            adapter_invariant("pin-key-observation", "duplicate-pin-key");
        }
        // Other commands may derive the same kind of key (e.g. hmac-secret).
        // Without an armed PIN attempt they must not create authorization.
    }

    pub fn has_pin_authorization(&self) -> bool {
        matches!(&*self.0.pin_access.borrow(), PinAccess::Granted(_))
    }

    /// Catch successful token issuance that skipped the TPM verification path.
    pub(crate) fn assert_pin_was_verified(&self) {
        if !self.has_pin_authorization() {
            adapter_invariant("token-issuance", "missing-tpm-authorization");
        }
    }

    /// Catch upstream reporting SetPIN/ChangePIN success without calling us.
    pub(crate) fn assert_pin_was_stored(&self) {
        if !matches!(&*self.0.pin_access.borrow(), PinAccess::PinStored) {
            adapter_invariant("pin-update", "missing-pin-storage");
        }
    }

    /// Call between commands only. OpenSK admits a command using its entry-time
    /// token validity, including commands that wait for desktop approval.
    pub fn expire_pin_authorization(&self, now_ms: u64) {
        let mut access = self.0.pin_access.borrow_mut();
        if matches!(&*access, PinAccess::Granted(grant) if now_ms >= grant.expires_at_ms) {
            *access = PinAccess::None;
        }
    }

    pub fn generate(&self) -> CtapResult<Blob> {
        let record = self.parent()?;
        let hash = self.hash()?;
        self.run(false, move |tpm, _| tpm.generate(&record, &hash))
    }

    pub fn sign(&self, key: &Blob, message: &[u8]) -> CtapResult<p256::ecdsa::Signature> {
        let record = self.parent()?;
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
    fn pin_hash(&self) -> CtapResult<Option<[u8; 16]>> {
        // A configured-PIN marker, never a software verifier or authorization.
        // KeyStore::decrypt_pin_hash checks this identity before adapting it.
        Ok(self.is_set()?.then_some(CONFIGURED_PIN_MARKER))
    }
    fn set_pin(&mut self, hash: &[u8; 16], length: u8) -> CtapResult<()> {
        if !(4..=63).contains(&length) {
            return Err(Status::CTAP2_ERR_PIN_POLICY_VIOLATION);
        }
        let new = Secret::from_exposed_secret(*hash);
        let record = if self.is_set()? {
            let record = self.parent()?;
            let old = self.hash()?;
            self.run(false, move |tpm, _| {
                tpm.change_pin(&record, &old, &new, length)
            })?
        } else {
            self.run(false, move |tpm, _| tpm.provision(&new, length))?
        };
        let result = self.write_record(
            PARENT,
            record
                .encode()
                .map_err(|_| Status::CTAP2_ERR_VENDOR_INTERNAL_ERROR)?,
        );
        self.clear();
        result?;
        self.remove(opensk::api::persist::keys::FORCE_PIN_CHANGE)?;
        // Command completion consumes this witness. It carries no authorization.
        *self.0.pin_access.borrow_mut() = PinAccess::PinStored;
        Ok(())
    }
}

impl Backend {
    fn is_set(&self) -> CtapResult<bool> {
        self.read_record(PARENT)?
            .map(|bytes| ParentRecord::decode(&bytes))
            .transpose()
            .map(|r| r.is_some())
            .map_err(|_| Status::CTAP2_ERR_VENDOR_INTERNAL_ERROR)
    }
    fn verify(&mut self, hash: &[u8; 16]) -> CtapResult<bool> {
        self.clear();
        let expires_at_ms = boot_ms().saturating_add(PIN_AUTHORIZATION_LIFETIME_MS);
        let record = self.parent()?;
        let hash = Secret::from_exposed_secret(*hash);
        let input = hash.clone();
        // Preserve wrong-authentication vs transport errors without turning an error into a grant.
        let answer = self.run(false, move |tpm, _| match tpm.verify(&record, &input) {
            Ok(master) => Ok(Some(master)),
            Err(Error::Tpm(tss_esapi::Error::Tss2Error(rc)))
                if matches!(rc.kind(), Some(RcKind::AuthFail | RcKind::BadAuth)) =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        })?;
        if let Some(master) = answer {
            *self.0.pin_access.borrow_mut() = PinAccess::Granted(Grant {
                pin_hash: hash,
                master,
                expires_at_ms,
            });
            Ok(true)
        } else {
            Ok(false)
        }
    }
    fn verify_candidate_for_opensk_comparison(&mut self) -> CtapResult<TpmPinComparison> {
        // Taking ownership both revokes pending access on error and releases the
        // RefCell borrow before TPM work pumps desktop callbacks.
        let access = self.0.pin_access.take();
        let (attempt, aes_key) = match access {
            PinAccess::Granted(grant) => {
                // A new attempt discarded the previous grant, so this can only
                // be ChangePIN's later read of this command's accepted old PIN.
                let hash = grant.pin_hash.clone();
                *self.0.pin_access.borrow_mut() = PinAccess::Granted(grant);
                return Ok(TpmPinComparison::Accepted(hash));
            }
            PinAccess::ReadyToVerify { attempt, aes_key } => (attempt, aes_key),
            other => {
                eprintln!(
                    "fidophir: fatal stage=pin-hash-decryption expected=ready-to-verify-or-granted actual={}",
                    other.phase()
                );
                adapter_invariant("pin-hash-decryption", "unexpected-pin-access-state")
            }
        };
        // Refuse to guess even once if an OpenSK upgrade skipped or reordered
        // retry charging. Storage guarantees this visible write is durable.
        attempt.assert_retry_was_charged(self.pin_fails()?);
        // Use the upstream v2 CBC helper, including its IV framing. A malformed
        // ciphertext cannot decrypt to 16 bytes in either copy of the operation;
        // return an arbitrary 16-byte value so upstream runs its mismatch path.
        let key = SoftwareAes256::new(&aes_key);
        let decrypted =
            match aes256_cbc_decrypt::<crate::env::LinuxEnv>(&key, &attempt.encrypted_hash, true) {
                Ok(hash) if hash.len() == 16 => hash,
                _ => return Ok(TpmPinComparison::MalformedCandidate),
            };
        let mut candidate = Secret::<[u8; 16]>::default();
        candidate.copy_from_slice(&decrypted);
        if self.verify(&candidate)? {
            Ok(TpmPinComparison::Accepted(candidate))
        } else {
            Ok(TpmPinComparison::Rejected(candidate))
        }
    }

    pub fn clear(&mut self) {
        *self.0.pin_access.borrow_mut() = PinAccess::None;
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
        _: CredentialSource,
    ) -> std::result::Result<Vec<u8>, key_store::Error> {
        Err(key_store::Error)
    }
    fn unwrap_credential(
        &mut self,
        _: &[u8],
        _: &[u8],
    ) -> std::result::Result<Option<CredentialSource>, key_store::Error> {
        Ok(None)
    }
    fn cred_random(&mut self, uv: bool) -> std::result::Result<Secret<[u8; 32]>, key_store::Error> {
        let access = self.0.pin_access.borrow();
        let PinAccess::Granted(grant) = &*access else {
            return Err(key_store::Error);
        };
        let mut key = Secret::<[u8; 32]>::default();
        let offset = if uv { 32 } else { 0 };
        key.copy_from_slice(&grant.master[offset..offset + 32]);
        Ok(key)
    }
    fn encrypt_pin_hash(
        &mut self,
        plain: &[u8; 16],
    ) -> std::result::Result<[u8; 16], key_store::Error> {
        // Passed directly to set_pin, which authorizes/wraps in TPM; never stored.
        Ok(*plain)
    }
    /// Adapt OpenSK's stored-verifier comparison to TPM PIN verification.
    ///
    /// We persist only CONFIGURED_PIN_MARKER. In the pinned OpenSK, a durable
    /// retry decrement precedes this callback; its result is then compared with
    /// the independently decrypted candidate. Return that candidate only after
    /// TPM acceptance, or a guaranteed mismatch on rejection, so OpenSK keeps
    /// its normal wrong-PIN counters and lockout behavior. The later same-PIN
    /// policy check during ChangePIN reads this command's accepted hash again.
    ///
    /// This intentionally diverges from KeyStore's decryption semantics. An
    /// OpenSK update that changes ordering, call sites, or ClientPIN derivation
    /// requires re-auditing the adapter contract and its regression tests.
    fn decrypt_pin_hash(
        &mut self,
        configured_pin_marker: &[u8; 16],
    ) -> std::result::Result<Secret<[u8; 16]>, key_store::Error> {
        if configured_pin_marker != &CONFIGURED_PIN_MARKER {
            adapter_invariant("pin-hash-decryption", "unexpected-configured-pin-marker");
        }
        self.verify_candidate_for_opensk_comparison()
            .map(TpmPinComparison::into_opensk_expected_hash)
            .map_err(|_| key_store::Error)
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
    fn random(_: &mut impl opensk::api::rng::Rng) -> Self {
        // OpenSK supplies no Env and no error return here. Never substitute a
        // software key or placeholder: a hardware failure ends this process.
        let backend = crate::opensk_adapter::scope::current_backend();
        Self(
            backend
                .generate()
                .unwrap_or_else(|status| fatal_crypto("credential-generation", status)),
        )
    }
    fn public_key(&self) -> VerifyingKey {
        VerifyingKey(
            self.0
                .verifying_key()
                .expect("validated Trusted Platform Module point"),
        )
    }
    fn sign(&self, message: &[u8]) -> Signature {
        let backend = crate::opensk_adapter::scope::current_backend();
        Signature(
            backend
                .sign(&self.0, message)
                .unwrap_or_else(|status| fatal_crypto("credential-signing", status)),
        )
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
    use opensk::api::crypto::{hkdf256::Hkdf256, rust_crypto::SoftwareHkdf256};

    // No worker or hardware: an accidental TPM/storage operation fails instead
    // of silently satisfying these tests through a mocked verification result.
    fn backend_without_worker() -> Backend {
        Backend(Rc::new(Inner {
            sender: None,
            worker: None,
            io: crate::io::Io::shared(),
            pin_access: RefCell::new(PinAccess::None),
        }))
    }

    fn grant(expires_at_ms: u64) -> PinAccess {
        PinAccess::Granted(Grant {
            pin_hash: Secret::from_exposed_secret([0x42; 16]),
            master: Secret::from_exposed_secret([0x24; 64]),
            expires_at_ms,
        })
    }

    #[test]
    fn same_pin_policy_read_reuses_verified_hash_without_tpm_work() {
        let mut backend = backend_without_worker();
        *backend.0.pin_access.borrow_mut() = grant(100);
        assert_eq!(
            &*backend.decrypt_pin_hash(&CONFIGURED_PIN_MARKER).unwrap(),
            &[0x42; 16]
        );
        assert!(backend.has_pin_authorization());
        backend.expire_pin_authorization(99);
        assert!(backend.has_pin_authorization());
        backend.expire_pin_authorization(100);
        assert!(!backend.has_pin_authorization());
    }

    #[test]
    fn hkdf_observation_preserves_crypto_and_requires_the_current_pin_request() {
        use crate::opensk_adapter::scope::{PinProtocolHkdf256, with_backend};
        let backend = backend_without_worker();
        let mut expected = [0; 32];
        let mut actual = [0; 32];
        SoftwareHkdf256::hkdf_empty_salt_256(&[0x21; 32], b"CTAP2 AES key", &mut expected);
        with_backend(&backend, || {
            // A real PIN-protocol key outside a pending request grants nothing.
            PinProtocolHkdf256::hkdf_empty_salt_256(&[0x21; 32], b"CTAP2 AES key", &mut actual);
            assert_eq!(actual, expected);
            assert!(!backend.has_pin_authorization());
            assert!(matches!(&*backend.0.pin_access.borrow(), PinAccess::None));

            *backend.0.pin_access.borrow_mut() = PinAccess::AwaitingKey(PinAttempt {
                encrypted_hash: vec![0; 32],
                expected_failure_count: 1,
            });
            PinProtocolHkdf256::hkdf_empty_salt_256(&[0x21; 32], b"CTAP2 HMAC key", &mut actual);
            assert!(matches!(
                &*backend.0.pin_access.borrow(),
                PinAccess::AwaitingKey(_)
            ));
            PinProtocolHkdf256::hkdf_empty_salt_256(&[0x21; 32], b"CTAP2 AES key", &mut actual);
            assert_eq!(actual, expected);
            match &*backend.0.pin_access.borrow() {
                PinAccess::ReadyToVerify { aes_key, .. } => assert_eq!(&**aes_key, &expected),
                _ => panic!("PIN key was not captured"),
            }
            assert!(!backend.has_pin_authorization());
        });
    }

    #[test]
    #[should_panic(expected = "reason=unexpected-configured-pin-marker")]
    fn wrong_configured_pin_marker_fails_even_with_a_grant() {
        let mut backend = backend_without_worker();
        *backend.0.pin_access.borrow_mut() = grant(100);
        let _ = backend.decrypt_pin_hash(&[0xa5; 16]);
    }
}
