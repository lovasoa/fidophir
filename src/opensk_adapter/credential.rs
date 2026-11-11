// SPDX-License-Identifier: Apache-2.0
//! Conversion between OpenSK credentials and host records.
use crate::{Error, Result, state::model::*};
use opensk::ctap::{
    cbor_read, cbor_write,
    data_formats::{
        CredentialProtectionPolicy, PublicKeyCredentialSource, PublicKeyCredentialType,
    },
};
pub struct OpenSkCodec;
fn policy(p: u8) -> Result<CredentialProtectionPolicy> {
    CredentialProtectionPolicy::try_from(sk_cbor::Value::unsigned(p.into()))
        .map_err(|_| Error::Invalid("invalid credential policy"))
}
impl CredentialCodec for OpenSkCodec {
    fn decode(&self, bytes: &[u8]) -> Result<ResidentCredential> {
        let c = cbor_read(bytes)
            .ok()
            .and_then(|v| PublicKeyCredentialSource::try_from(v).ok())
            .ok_or(Error::Invalid("invalid credential CBOR"))?;
        Ok(ResidentCredential {
            credential_id: c.credential_id,
            wrapped_private_key: c.wrapped_private_key,
            rp_id: c.rp_id,
            user_handle: c.user_handle,
            user_display_name: c.user_display_name,
            cred_protect_policy: c.cred_protect_policy.map(|p| p as u8),
            creation_order: c.creation_order,
            user_name: c.user_name,
            user_icon: c.user_icon,
            cred_blob: c.cred_blob,
            large_blob_key: c.large_blob_key,
        })
    }
    fn encode(&self, c: ResidentCredential) -> Result<Vec<u8>> {
        let c = PublicKeyCredentialSource {
            key_type: PublicKeyCredentialType::PublicKey,
            credential_id: c.credential_id,
            wrapped_private_key: c.wrapped_private_key,
            rp_id: c.rp_id,
            user_handle: c.user_handle,
            user_display_name: c.user_display_name,
            cred_protect_policy: c.cred_protect_policy.map(policy).transpose()?,
            creation_order: c.creation_order,
            user_name: c.user_name,
            user_icon: c.user_icon,
            cred_blob: c.cred_blob,
            large_blob_key: c.large_blob_key,
        };
        let mut bytes = Vec::new();
        cbor_write(c.into(), &mut bytes).map_err(|_| Error::Invalid("credential encoding"))?;
        Ok(bytes)
    }
}
impl From<opensk::api::key_store::CredentialSource> for CredentialSource {
    fn from(c: opensk::api::key_store::CredentialSource) -> Self {
        Self {
            wrapped_private_key: c.wrapped_private_key,
            rp_id_hash: c.rp_id_hash,
            cred_protect_policy: c.cred_protect_policy.map(|p| p as u8),
            cred_blob: c.cred_blob,
        }
    }
}
impl TryFrom<CredentialSource> for opensk::api::key_store::CredentialSource {
    type Error = Error;
    fn try_from(c: CredentialSource) -> Result<Self> {
        Ok(Self {
            wrapped_private_key: c.wrapped_private_key,
            rp_id_hash: c.rp_id_hash,
            cred_protect_policy: c.cred_protect_policy.map(policy).transpose()?,
            cred_blob: c.cred_blob,
        })
    }
}
