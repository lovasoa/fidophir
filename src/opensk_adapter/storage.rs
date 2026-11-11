// SPDX-License-Identifier: Apache-2.0
//! OpenSK persistence and key-store translation. Core operations return host errors.
use crate::{backend::Backend, core, state::Store, tpm::Tpm};
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
const CONFIGURED_PIN_MARKER: [u8; 16] = [0; 16];
#[derive(Clone)]
pub struct Storage(pub Backend);
impl Storage {
    fn run<T: Send + 'static>(
        &self,
        durable: bool,
        f: impl FnOnce(&mut Tpm, &Store) -> crate::Result<T> + Send + 'static,
    ) -> CtapResult<T> {
        self.0.run(durable, f).map_err(status)
    }
    fn write_record(&self, key: usize, bytes: Vec<u8>) -> CtapResult<()> {
        self.0.write_record(key, bytes).map_err(status)
    }
}
pub(crate) fn status(error: core::BackendError) -> Status {
    match error {
        core::BackendError::Cancelled => Status::CTAP2_ERR_KEEPALIVE_CANCEL,
        core::BackendError::PinBlocked => Status::CTAP2_ERR_PIN_AUTH_BLOCKED,
        core::BackendError::Hardware => Status::CTAP2_ERR_VENDOR_HARDWARE_FAILURE,
        core::BackendError::Internal => Status::CTAP2_ERR_VENDOR_INTERNAL_ERROR,
        core::BackendError::AuthorizationRequired => Status::CTAP2_ERR_PUAT_REQUIRED,
        core::BackendError::PinNotSet => Status::CTAP2_ERR_PIN_NOT_SET,
    }
}
impl Persist for Storage {
    fn find(&self, key: usize) -> CtapResult<Option<Vec<u8>>> {
        if key > 4095 {
            return Err(Status::CTAP2_ERR_VENDOR_INTERNAL_ERROR);
        }
        self.0.read_record(key).map_err(status)
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
        Ok(self
            .0
            .has_pin()
            .map_err(status)?
            .then_some(CONFIGURED_PIN_MARKER))
    }
    fn set_pin(&mut self, hash: &[u8; 16], length: u8) -> CtapResult<()> {
        self.0.store_pin(hash, length).map_err(status)?;
        self.remove(opensk::api::persist::keys::FORCE_PIN_CHANGE)
    }
}

impl KeyStore for Storage {
    fn init(&mut self) -> std::result::Result<(), key_store::Error> {
        Ok(())
    }
    fn reset(&mut self) -> std::result::Result<(), key_store::Error> {
        self.0.clear();
        Ok(())
    }
    fn wrap_credential(
        &mut self,
        credential: CredentialSource,
    ) -> std::result::Result<Vec<u8>, key_store::Error> {
        self.run(true, move |_, store| {
            store.create_non_discoverable(credential.into())
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
            store
                .read_non_discoverable(&id, &rp_hash)?
                .map(TryInto::try_into)
                .transpose()
        })
        .map_err(|_| key_store::Error)
    }
    fn cred_random(&mut self, uv: bool) -> std::result::Result<Secret<[u8; 32]>, key_store::Error> {
        self.0
            .credential_random(uv)
            .map(|key| Secret::from_exposed_secret(*key))
            .map_err(|_| key_store::Error)
    }
    fn encrypt_pin_hash(
        &mut self,
        plain: &[u8; 16],
    ) -> std::result::Result<[u8; 16], key_store::Error> {
        Ok(*plain)
    }
    fn verify_pin_hash(
        &mut self,
        _stored: &[u8; 16],
        candidate: &[u8; 16],
    ) -> std::result::Result<bool, key_store::Error> {
        if let Some(matches) = self.0.matches_authorized_pin(candidate) {
            return Ok(matches);
        }
        match self.0.verify(candidate) {
            Err(core::BackendError::PinBlocked) => {
                // OpenSK durably charged an attempt; a TPM lockout never checked it.
                let failures = self.pin_fails().map_err(|_| key_store::Error)?;
                self.write_record(
                    opensk::api::persist::keys::PIN_RETRIES,
                    vec![failures.saturating_sub(1)],
                )
                .map_err(|_| key_store::Error)?;
                Err(key_store::Error)
            }
            answer => answer.map_err(|_| key_store::Error),
        }
    }
}
