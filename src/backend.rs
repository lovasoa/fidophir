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
        key_store::{self, CredentialSource, KeyStore},
        persist::{Persist, PersistIter},
        pin::PinAuthority,
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
use subtle::ConstantTimeEq;
use tss_esapi::{constants::response_code::Tss2ResponseCodeKind as RcKind, tcti_ldr::TctiNameConf};

type Task = Box<dyn FnOnce(&mut Tpm, &Store) + Send>;
struct Grant {
    hash: Secret<[u8; 16]>,
    master: Secret<[u8; 64]>,
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

fn fatal(message: &'static str) -> ! {
    eprintln!("fidophir: {message}");
    std::process::exit(1)
}

fn status(error: &Error) -> Status {
    if let Error::Tpm(tss_esapi::Error::Tss2Error(rc)) = error
        && rc.kind() == Some(RcKind::Lockout)
    {
        return Status::CTAP2_ERR_PIN_AUTH_BLOCKED;
    }
    Status::CTAP2_ERR_VENDOR_HARDWARE_FAILURE
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
                    if let Some(record) = store.read(PARENT)? {
                        ParentRecord::decode(&record)?;
                    }
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
            match result.try_recv() {
                Ok(Err(_)) if durable => fatal("durable state update failed; refusing to continue"),
                Ok(answer) => {
                    if !durable && self.0.io.borrow().cancelled() {
                        return Err(Status::CTAP2_ERR_KEEPALIVE_CANCEL);
                    }
                    return answer.map_err(|e| status(&e));
                }
                Err(mpsc::TryRecvError::Disconnected) => fatal("I/O worker stopped"),
                Err(mpsc::TryRecvError::Empty) => (),
            }
            if boot_ms() >= deadline {
                fatal("I/O worker timed out");
            }
            std::thread::sleep(Duration::from_millis(5));
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
        self.0
            .grant
            .borrow()
            .as_ref()
            .map(|g| g.hash.clone())
            .ok_or(Status::CTAP2_ERR_PUAT_REQUIRED)
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
    fn reset(&mut self) -> CtapResult<()> {
        Err(Status::CTAP2_ERR_NOT_ALLOWED)
    }
    fn global_signature_counter(&self) -> CtapResult<u32> {
        Ok(0)
    }
    fn pin_hash(&self) -> CtapResult<Option<[u8; 16]>> {
        Err(Status::CTAP2_ERR_VENDOR_INTERNAL_ERROR)
    }
    fn set_pin(&mut self, _: &[u8; 16], _: u8) -> CtapResult<()> {
        Err(Status::CTAP2_ERR_VENDOR_INTERNAL_ERROR)
    }
}

impl PinAuthority for Backend {
    fn is_set(&self) -> CtapResult<bool> {
        self.read_record(PARENT)?
            .map(|bytes| ParentRecord::decode(&bytes))
            .transpose()
            .map(|r| r.is_some())
            .map_err(|_| Status::CTAP2_ERR_VENDOR_INTERNAL_ERROR)
    }
    fn install(&mut self, hash: &[u8; 16], length: u8) -> CtapResult<()> {
        if self.is_set()? || !(8..=63).contains(&length) {
            return Err(Status::CTAP2_ERR_PIN_AUTH_INVALID);
        }
        let hash = Secret::from_exposed_secret(*hash);
        let record = self.run(false, move |tpm, _| tpm.provision(&hash, length))?;
        self.write_record(
            PARENT,
            record
                .encode()
                .map_err(|_| Status::CTAP2_ERR_VENDOR_INTERNAL_ERROR)?,
        )?;
        self.clear();
        Ok(())
    }
    fn verify(&mut self, hash: &[u8; 16]) -> CtapResult<bool> {
        self.clear();
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
            *self.0.grant.borrow_mut() = Some(Grant { hash, master });
            Ok(true)
        } else {
            Ok(false)
        }
    }
    fn replace_verified(&mut self, new: &[u8; 16], length: u8) -> CtapResult<()> {
        let record = self.parent()?;
        let old = self.hash()?;
        let new = Secret::from_exposed_secret(*new);
        let next = self.run(false, move |tpm, _| {
            tpm.change_pin(&record, &old, &new, length)
        })?;
        let result = self.write_record(
            PARENT,
            next.encode()
                .map_err(|_| Status::CTAP2_ERR_VENDOR_INTERNAL_ERROR)?,
        );
        self.clear();
        result
    }
    fn matches_verified(&self, hash: &[u8; 16]) -> bool {
        self.0
            .grant
            .borrow()
            .as_ref()
            .is_some_and(|g| bool::from(g.hash.as_slice().ct_eq(hash)))
    }
    fn clear(&mut self) {
        self.0.grant.borrow_mut().take();
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
        let grant = self.0.grant.borrow();
        let grant = grant.as_ref().ok_or(key_store::Error)?;
        let mut key = Secret::<[u8; 32]>::default();
        let offset = if uv { 32 } else { 0 };
        key.copy_from_slice(&grant.master[offset..offset + 32]);
        Ok(key)
    }
    fn encrypt_pin_hash(
        &mut self,
        _: &[u8; 16],
    ) -> std::result::Result<[u8; 16], key_store::Error> {
        Err(key_store::Error)
    }
    fn decrypt_pin_hash(
        &mut self,
        _: &[u8; 16],
    ) -> std::result::Result<Secret<[u8; 16]>, key_store::Error> {
        Err(key_store::Error)
    }
}

pub struct TpmEcdsa;
pub struct SigningKey(Blob);
pub struct VerifyingKey(p256::ecdsa::VerifyingKey);
pub struct Signature(p256::ecdsa::Signature);

impl opensk::api::crypto::ec_signing::Ecdsa for TpmEcdsa {
    type Context = Backend;
    type SecretKey = SigningKey;
    type PublicKey = VerifyingKey;
    type Signature = Signature;
}
impl opensk::api::crypto::ec_signing::EcSecretKey for SigningKey {
    type Context = Backend;
    type PublicKey = VerifyingKey;
    type Signature = Signature;
    fn random(_: &mut impl opensk::api::rng::Rng, backend: &mut Backend) -> CtapResult<Self> {
        backend.generate().map(Self)
    }
    fn public_key(&self) -> VerifyingKey {
        VerifyingKey(self.0.verifying_key().expect("validated TPM point"))
    }
    fn sign(&self, message: &[u8], backend: &mut Backend) -> CtapResult<Signature> {
        backend.sign(&self.0, message).map(Signature)
    }
    fn export(&self) -> Vec<u8> {
        self.0.encode().expect("bounded TPM blob encoding")
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
