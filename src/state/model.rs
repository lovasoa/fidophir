// SPDX-License-Identifier: Apache-2.0
//! Host credential records, independent of the CTAP serialization format.
pub struct ResidentCredential {
    pub credential_id: Vec<u8>,
    pub wrapped_private_key: sk_cbor::Value,
    pub rp_id: String,
    pub user_handle: Vec<u8>,
    pub user_display_name: Option<String>,
    pub cred_protect_policy: Option<u8>,
    pub creation_order: u64,
    pub user_name: Option<String>,
    pub user_icon: Option<String>,
    pub cred_blob: Option<Vec<u8>>,
    pub large_blob_key: Option<Vec<u8>>,
}
pub struct CredentialSource {
    pub wrapped_private_key: sk_cbor::Value,
    pub rp_id_hash: [u8; 32],
    pub cred_protect_policy: Option<u8>,
    pub cred_blob: Option<Vec<u8>>,
}
pub trait CredentialCodec: Sync {
    fn decode(&self, bytes: &[u8]) -> crate::Result<ResidentCredential>;
    fn encode(&self, credential: ResidentCredential) -> crate::Result<Vec<u8>>;
}
