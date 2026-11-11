// SPDX-License-Identifier: Apache-2.0
//! INI and binary files are authoritative; CBOR is only the OpenSK interface.
use super::model::{CredentialSource, ResidentCredential};
use super::*;
use sk_cbor::Value;

const GROUP: &str = "credential";

/// Key material and policy shared by both discovery modes.
struct CredentialKey {
    wrapped_private_key: Value,
    protection: Option<u8>,
    blob: Option<Vec<u8>>,
}

impl CredentialKey {
    fn into_source(self, rp_id_hash: [u8; 32]) -> CredentialSource {
        CredentialSource {
            wrapped_private_key: self.wrapped_private_key,
            rp_id_hash,
            cred_protect_policy: self.protection,
            cred_blob: self.blob,
        }
    }
}

/// One credential directory, shared by both discovery modes.
struct CredentialDirectory<'a> {
    store: &'a Store,
    path: &'a Path,
    metadata: glib::KeyFile,
}

impl<'a> CredentialDirectory<'a> {
    fn new(store: &'a Store, path: &'a Path) -> Self {
        let metadata = glib::KeyFile::new();
        metadata.set_uint64(GROUP, "format_version", 1);
        Self {
            store,
            path,
            metadata,
        }
    }

    fn open(store: &'a Store, path: &'a Path) -> Result<Self> {
        store.check_dir(path)?;
        let record = Self::new(store, path);
        let bytes = record.required("metadata.ini")?;
        let text = std::str::from_utf8(&bytes).map_err(|_| record.invalid("UTF-8"))?;
        record
            .metadata
            .load_from_data(text, glib::KeyFileFlags::NONE)
            .map_err(|_| record.invalid("INI syntax"))?;
        if record.number("format_version")? != Some(1) {
            return Err(record.invalid("format_version"));
        }
        Ok(record)
    }

    fn invalid(&self, field: &str) -> Error {
        invalid_credential(
            &self.path.join("metadata.ini"),
            format!("invalid or missing {field}; check README.txt"),
        )
    }

    fn required(&self, name: &str) -> Result<Vec<u8>> {
        self.store.read_file(&self.path.join(name))?.ok_or_else(|| {
            invalid_credential(
                &self.path.join(name),
                "missing required file; restore it or remove this credential directory",
            )
        })
    }

    fn text(&self, name: &str) -> Result<Option<String>> {
        if !self.metadata.has_key(GROUP, name).unwrap_or(false) {
            return Ok(None);
        }
        self.metadata
            .string(GROUP, name)
            .map(|s| Some(s.to_string()))
            .map_err(|_| self.invalid(name))
    }

    fn number(&self, name: &str) -> Result<Option<u64>> {
        if !self.metadata.has_key(GROUP, name).unwrap_or(false) {
            return Ok(None);
        }
        self.metadata
            .uint64(GROUP, name)
            .map(Some)
            .map_err(|_| self.invalid(name))
    }

    fn set_text(&self, name: &str, value: Option<&str>) -> Result<()> {
        if let Some(value) = value {
            if value.contains('\0') {
                return Err(self.invalid(name));
            }
            self.metadata.set_string(GROUP, name, value);
        }
        Ok(())
    }

    fn save_metadata(&self) -> Result<()> {
        self.store.write_file(
            &self.path.join("metadata.ini"),
            self.metadata.to_data().as_bytes(),
        )
    }

    fn write_binary(&self, name: &str, bytes: Option<&[u8]>) -> Result<()> {
        if let Some(bytes) = bytes {
            self.store.write_file(&self.path.join(name), bytes)?;
        }
        Ok(())
    }

    fn write_key(&self, key: Value, policy: Option<u8>, cred_blob: Option<&[u8]>) -> Result<()> {
        let blob = signing_blob(key)?;
        validate_signing_blob(&blob)?;
        if let Some(policy) = policy {
            self.metadata
                .set_uint64(GROUP, "cred_protect_policy", policy as u64);
        }
        self.write_binary("tpm-signing-blob.bin", Some(&blob))?;
        self.write_binary("cred-blob.bin", cred_blob)
    }

    fn read_key(&self) -> Result<CredentialKey> {
        let blob = self.required("tpm-signing-blob.bin")?;
        validate_signing_blob(&blob).map_err(|_| {
            invalid_credential(
                &self.path.join("tpm-signing-blob.bin"),
                "invalid Trusted Platform Module signing blob; restore from backup",
            )
        })?;
        let policy = self
            .number("cred_protect_policy")?
            .map(|p| {
                u8::try_from(p)
                    .ok()
                    .filter(|p| (1..=3).contains(p))
                    .ok_or(())
            })
            .transpose()
            .map_err(|_| self.invalid("cred_protect_policy"))?;
        Ok(CredentialKey {
            wrapped_private_key: sk_cbor::cbor_array![-7, blob],
            protection: policy,
            blob: self.store.read_file(&self.path.join("cred-blob.bin"))?,
        })
    }
}

fn signing_blob(wrapper: Value) -> Result<Vec<u8>> {
    let fields = wrapper
        .extract_array()
        .ok_or(Error::Invalid("invalid signing-key wrapper"))?;
    let [algorithm, blob]: [Value; 2] = fields
        .try_into()
        .map_err(|_| Error::Invalid("invalid signing-key wrapper"))?;
    if algorithm != sk_cbor::cbor_int!(-7) {
        return Err(Error::Invalid("unsupported signing algorithm"));
    }
    blob.extract_byte_string()
        .ok_or(Error::Invalid("invalid signing blob"))
}

fn validate_signing_blob(bytes: &[u8]) -> Result<()> {
    crate::tpm::Blob::decode(bytes, crate::tpm::Kind::Signing)?.verifying_key()?;
    Ok(())
}

pub(super) fn write(store: &Store, path: &Path, bytes: &[u8]) -> Result<()> {
    let c = store
        .codec
        .decode(bytes)
        .map_err(|_| problem(path, "invalid credential CBOR"))?;
    let record = CredentialDirectory::new(store, path);
    record
        .metadata
        .set_uint64(GROUP, "creation_order", c.creation_order);
    for (name, value) in [
        ("rp_id", Some(c.rp_id)),
        ("user_name", c.user_name),
        ("user_display_name", c.user_display_name),
        ("user_icon", c.user_icon),
    ] {
        record.set_text(name, value.as_deref())?;
    }
    record.write_key(
        c.wrapped_private_key,
        c.cred_protect_policy,
        c.cred_blob.as_deref(),
    )?;
    record.write_binary("credential-id.bin", Some(&c.credential_id))?;
    record.write_binary("user-handle.bin", Some(&c.user_handle))?;
    record.write_binary("large-blob-key.bin", c.large_blob_key.as_deref())?;
    record.save_metadata()
}

pub(super) fn read(store: &Store, path: &Path) -> Result<Vec<u8>> {
    let record = CredentialDirectory::open(store, path)?;
    let key = record.read_key()?;
    let c = ResidentCredential {
        credential_id: record.required("credential-id.bin")?,
        wrapped_private_key: key.wrapped_private_key,
        rp_id: record
            .text("rp_id")?
            .ok_or_else(|| record.invalid("rp_id"))?,
        user_handle: record.required("user-handle.bin")?,
        user_display_name: record.text("user_display_name")?,
        cred_protect_policy: key.protection,
        creation_order: record.number("creation_order")?.unwrap_or(0),
        user_name: record.text("user_name")?,
        user_icon: record.text("user_icon")?,
        cred_blob: key.blob,
        large_blob_key: store.read_file(&path.join("large-blob-key.bin"))?,
    };
    if c.credential_id.len() != 32 || c.user_handle.len() > 64 || c.rp_id.is_empty() {
        return Err(invalid_credential(
            path,
            "invalid credential ID, user handle or RP ID",
        ));
    }
    let bytes = store
        .codec
        .encode(c)
        .map_err(|_| record.invalid("credential encoding"))?;
    if bytes.len() > MAX_VALUE {
        return Err(invalid_credential(path, "credential exceeds 4096 bytes"));
    }
    Ok(bytes)
}

pub(super) fn write_non_discoverable(
    store: &Store,
    path: &Path,
    id: &[u8; 32],
    source: CredentialSource,
) -> Result<()> {
    let record = CredentialDirectory::new(store, path);
    record.set_text("rp_id_hash", Some(&hex_id(&source.rp_id_hash)))?;
    record.write_key(
        source.wrapped_private_key,
        source.cred_protect_policy,
        source.cred_blob.as_deref(),
    )?;
    record.write_binary("credential-id.bin", Some(id))?;
    record.save_metadata()
}

pub(super) fn read_non_discoverable(
    store: &Store,
    path: &Path,
    id: &[u8; 32],
    rp_hash: &[u8; 32],
) -> Result<Option<CredentialSource>> {
    let record = CredentialDirectory::open(store, path)?;
    let stored_id = record.required("credential-id.bin")?;
    if stored_id.len() != 32 {
        return Err(record.invalid("credential ID"));
    }
    if stored_id != id {
        return Ok(None);
    }
    let stored_hash = record
        .text("rp_id_hash")?
        .ok_or_else(|| record.invalid("rp_id_hash"))?;
    if stored_hash.len() != 64
        || !stored_hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(record.invalid("rp_id_hash"));
    }
    if stored_hash != hex_id(rp_hash) {
        return Ok(None);
    }
    Ok(Some(record.read_key()?.into_source(*rp_hash)))
}
