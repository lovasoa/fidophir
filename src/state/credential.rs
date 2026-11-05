// SPDX-License-Identifier: Apache-2.0
//! INI and binary files are authoritative; CBOR is only the OpenSK interface.
use super::*;
use opensk::ctap::{
    cbor_read, cbor_write,
    data_formats::{
        CredentialProtectionPolicy, PublicKeyCredentialSource, PublicKeyCredentialType,
    },
};

const GROUP: &str = "credential";

pub(super) fn write(store: &Store, path: &Path, bytes: &[u8]) -> Result<()> {
    let c = cbor_read(bytes)
        .ok()
        .and_then(|v| PublicKeyCredentialSource::try_from(v).ok())
        .ok_or_else(|| problem(path, "invalid credential CBOR"))?;
    let ini = glib::KeyFile::new();
    ini.set_uint64(GROUP, "format_version", 1);
    ini.set_uint64(GROUP, "creation_order", c.creation_order);
    if let Some(policy) = c.cred_protect_policy {
        ini.set_uint64(GROUP, "cred_protect_policy", policy as u64);
    }
    for (name, value) in [
        ("rp_id", Some(c.rp_id)),
        ("user_name", c.user_name),
        ("user_display_name", c.user_display_name),
        ("user_icon", c.user_icon),
    ] {
        if let Some(value) = value {
            if value.contains('\0') {
                return Err(problem(path, "metadata strings cannot contain NUL"));
            }
            ini.set_string(GROUP, name, &value);
        }
    }
    let fields = c
        .wrapped_private_key
        .extract_array()
        .ok_or_else(|| problem(path, "invalid signing-key wrapper"))?;
    let [algorithm, blob]: [sk_cbor::Value; 2] = fields
        .try_into()
        .map_err(|_| problem(path, "invalid signing-key wrapper"))?;
    if algorithm != sk_cbor::cbor_int!(-7) {
        return Err(problem(path, "unsupported signing algorithm"));
    }
    let blob = blob
        .extract_byte_string()
        .ok_or_else(|| problem(path, "invalid signing blob"))?;
    for (name, value) in [
        ("metadata.ini", Some(ini.to_data().as_bytes().to_vec())),
        ("credential-id.bin", Some(c.credential_id)),
        ("user-handle.bin", Some(c.user_handle)),
        ("tpm-signing-blob.bin", Some(blob)),
        ("cred-blob.bin", c.cred_blob),
        ("large-blob-key.bin", c.large_blob_key),
    ] {
        if let Some(value) = value {
            store.write_file(&path.join(name), &value)?;
        }
    }
    Ok(())
}

pub(super) fn read(store: &Store, path: &Path) -> Result<Vec<u8>> {
    store.check_dir(path)?;
    let required = |name: &str| {
        store.read_file(&path.join(name))?.ok_or_else(|| {
            invalid_credential(
                &path.join(name),
                "missing required file; restore it or remove this credential directory",
            )
        })
    };
    let meta_path = path.join("metadata.ini");
    let bytes = required("metadata.ini")?;
    let ini = glib::KeyFile::new();
    let invalid = |name: &str| {
        invalid_credential(
            &meta_path,
            format!("invalid or missing {name}; check README.txt"),
        )
    };
    ini.load_from_data(
        std::str::from_utf8(&bytes).map_err(|_| invalid("UTF-8"))?,
        glib::KeyFileFlags::NONE,
    )
    .map_err(|_| invalid("INI syntax"))?;
    if ini
        .uint64(GROUP, "format_version")
        .map_err(|_| invalid("format_version"))?
        != 1
    {
        return Err(invalid_credential(&meta_path, "unsupported format_version"));
    }
    let text = |name: &str| -> Result<Option<String>> {
        if !ini.has_key(GROUP, name).unwrap_or(false) {
            return Ok(None);
        }
        ini.string(GROUP, name)
            .map(|s| Some(s.to_string()))
            .map_err(|_| invalid(name))
    };
    let number = |name: &str| -> Result<Option<u64>> {
        if !ini.has_key(GROUP, name).unwrap_or(false) {
            return Ok(None);
        }
        ini.uint64(GROUP, name).map(Some).map_err(|_| invalid(name))
    };
    let blob_path = path.join("tpm-signing-blob.bin");
    let blob = required("tpm-signing-blob.bin")?;
    let key = crate::tpm::Blob::decode(&blob, crate::tpm::Kind::Signing).map_err(|_| {
        invalid_credential(
            &blob_path,
            "invalid Trusted Platform Module signing blob; restore from backup",
        )
    })?;
    key.verifying_key().map_err(|_| {
        invalid_credential(&blob_path, "invalid Trusted Platform Module public point")
    })?;
    let c = PublicKeyCredentialSource {
        key_type: PublicKeyCredentialType::PublicKey,
        credential_id: required("credential-id.bin")?,
        wrapped_private_key: sk_cbor::cbor_array![-7, blob],
        rp_id: text("rp_id")?.ok_or_else(|| invalid("rp_id"))?,
        user_handle: required("user-handle.bin")?,
        user_display_name: text("user_display_name")?,
        cred_protect_policy: number("cred_protect_policy")?
            .map(|p| CredentialProtectionPolicy::try_from(sk_cbor::Value::unsigned(p)))
            .transpose()
            .map_err(|_| invalid("cred_protect_policy"))?,
        creation_order: number("creation_order")?.unwrap_or(0),
        user_name: text("user_name")?,
        user_icon: text("user_icon")?,
        cred_blob: store.read_file(&path.join("cred-blob.bin"))?,
        large_blob_key: store.read_file(&path.join("large-blob-key.bin"))?,
    };
    if c.credential_id.len() != 32 || c.user_handle.len() > 64 || c.rp_id.is_empty() {
        return Err(invalid_credential(
            path,
            "invalid credential ID, user handle or RP ID",
        ));
    }
    let mut bytes = Vec::new();
    cbor_write(c.into(), &mut bytes).map_err(|_| invalid("credential encoding"))?;
    if bytes.len() > MAX_VALUE {
        return Err(invalid_credential(path, "credential exceeds 4096 bytes"));
    }
    Ok(bytes)
}
