// SPDX-License-Identifier: Apache-2.0
//! OpenSK signing traits; only this adapter uses the dispatch scope.
use crate::tpm::{Blob, Kind};
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
