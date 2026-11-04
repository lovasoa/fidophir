// SPDX-License-Identifier: Apache-2.0
//! TPM storage hierarchy. Signing scalars are generated and used only inside TPM.
use crate::{Error, Result};
use opensk::ctap::{cbor_read, cbor_write, secret::Secret};
use rand::{TryRng, rngs::SysRng};
use sha2::{Digest as _, Sha256};
use sk_cbor::{Value, cbor_array};
use tss_esapi::{
    Context,
    attributes::{ObjectAttributes, ObjectAttributesBuilder, SessionAttributesBuilder},
    constants::{SessionType, StructureTag},
    handles::{KeyHandle, SessionHandle},
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        ecc::EccCurve,
        resource_handles::Hierarchy,
    },
    structures::*,
    tcti_ldr::TctiNameConf,
    traits::{Marshall, UnMarshall},
};

#[derive(Clone)]
pub struct Blob {
    pub public: Public,
    pub private: Private,
}

impl Blob {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        cbor_write(
            cbor_array![1, self.public.marshall()?, self.private.value().to_vec()],
            &mut out,
        )
        .map_err(|_| Error::Invalid("key encoding failed"))?;
        Ok(out)
    }

    pub fn decode(bytes: &[u8], kind: Kind) -> Result<Self> {
        if bytes.len() > 1100 {
            return Err(Error::Invalid("oversized TPM blob"));
        }
        let fields = cbor_read(bytes)
            .ok()
            .and_then(Value::extract_array)
            .ok_or(Error::Invalid("invalid key encoding"))?;
        let [version, public, private]: [Value; 3] = fields
            .try_into()
            .map_err(|_| Error::Invalid("invalid key encoding"))?;
        let public = public
            .extract_byte_string()
            .ok_or(Error::Invalid("invalid public blob"))?;
        let private = private
            .extract_byte_string()
            .ok_or(Error::Invalid("invalid private blob"))?;
        if version.extract_unsigned() != Some(1)
            || public.len() > 512
            || private.len() > 512
            || private.is_empty()
        {
            return Err(Error::Invalid("invalid TPM blob bounds/version"));
        }
        let p = Public::unmarshall(&public)?;
        if p.marshall()? != public {
            return Err(Error::Invalid("noncanonical TPM public blob"));
        }
        validate(&p, kind)?;
        Ok(Self {
            public: p,
            private: Private::try_from(private.clone())?,
        })
    }

    pub fn verifying_key(&self) -> Result<p256::ecdsa::VerifyingKey> {
        let Public::Ecc { unique, .. } = &self.public else {
            return Err(Error::Invalid("key is not ECC"));
        };
        let x = coordinate(unique.x().value())?;
        let y = coordinate(unique.y().value())?;
        let point = p256::Sec1Point::from_affine_coordinates((&x).into(), (&y).into(), false);
        p256::ecdsa::VerifyingKey::from_sec1_bytes(point.as_bytes())
            .map_err(|_| Error::Invalid("invalid TPM point"))
    }
}

fn coordinate(input: &[u8]) -> Result<[u8; 32]> {
    if input.is_empty() || input.len() > 32 {
        return Err(Error::Invalid("invalid P-256 coordinate"));
    }
    let mut out = [0; 32];
    out[32 - input.len()..].copy_from_slice(input);
    Ok(out)
}

#[derive(Clone, Copy)]
pub enum Kind {
    Root,
    Parent,
    Check,
    Signing,
}

fn attributes(kind: Kind) -> tss_esapi::Result<ObjectAttributes> {
    let storage = matches!(kind, Kind::Root | Kind::Parent);
    ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_user_with_auth(true)
        .with_sensitive_data_origin(!matches!(kind, Kind::Check))
        .with_no_da(!matches!(kind, Kind::Parent))
        .with_restricted(storage)
        .with_decrypt(storage)
        .with_sign_encrypt(matches!(kind, Kind::Signing))
        .build()
}

fn template(kind: Kind) -> tss_esapi::Result<Public> {
    let builder = PublicBuilder::new()
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes(kind)?)
        .with_auth_policy(Digest::default());
    if matches!(kind, Kind::Check) {
        builder
            .with_public_algorithm(PublicAlgorithm::KeyedHash)
            .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Null))
            .with_keyed_hash_unique_identifier(Digest::default())
            .build()
    } else {
        let parameters = if matches!(kind, Kind::Signing) {
            PublicEccParametersBuilder::new_unrestricted_signing_key(
                EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)),
                EccCurve::NistP256,
            )
        } else {
            PublicEccParametersBuilder::new_restricted_decryption_key(
                SymmetricDefinitionObject::AES_128_CFB,
                EccCurve::NistP256,
            )
        }
        .build()?;
        builder
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_ecc_parameters(parameters)
            .with_ecc_unique_identifier(EccPoint::default())
            .build()
    }
}

fn validate(public: &Public, kind: Kind) -> Result<()> {
    let expected = template(kind)?;
    let matches = match (public, expected) {
        (Public::Ecc { parameters: a, .. }, Public::Ecc { parameters: b, .. }) => *a == b,
        (Public::KeyedHash { parameters: a, .. }, Public::KeyedHash { parameters: b, .. }) => {
            *a == b
        }
        _ => false,
    };
    if !matches
        || public.object_attributes() != attributes(kind)?
        || public.name_hashing_algorithm() != HashingAlgorithm::Sha256
        || !public.auth_policy().value().is_empty()
    {
        return Err(Error::Invalid("unexpected TPM object template"));
    }
    Ok(())
}

#[derive(Clone)]
pub struct ParentRecord {
    pub parent: Blob,
    pub check: Blob,
    pub pin_length: u8,
}

impl ParentRecord {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        cbor_write(
            cbor_array![
                1,
                self.parent.encode()?,
                self.check.encode()?,
                self.pin_length as u64
            ],
            &mut out,
        )
        .map_err(|_| Error::Invalid("parent encoding failed"))?;
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let fields = cbor_read(bytes)
            .ok()
            .and_then(Value::extract_array)
            .ok_or(Error::Invalid("invalid parent record"))?;
        let [version, p, s, length]: [Value; 4] = fields
            .try_into()
            .map_err(|_| Error::Invalid("invalid parent record"))?;
        let p = p
            .extract_byte_string()
            .ok_or(Error::Invalid("invalid parent blob"))?;
        let s = s
            .extract_byte_string()
            .ok_or(Error::Invalid("invalid check blob"))?;
        let length = length
            .extract_unsigned()
            .ok_or(Error::Invalid("invalid PIN length"))?;
        if version.extract_unsigned() != Some(1) || !(8..=63).contains(&length) {
            return Err(Error::Invalid("invalid PIN metadata"));
        }
        Ok(Self {
            parent: Blob::decode(&p, Kind::Parent)?,
            check: Blob::decode(&s, Kind::Check)?,
            pin_length: length as u8,
        })
    }
}

pub struct Tpm {
    context: Context,
    root: KeyHandle,
}

/// A salted, parameter-protected HMAC session. Scope it with the library's helper.
fn protected<T>(
    ctx: &mut Context,
    salt: KeyHandle,
    decrypt: bool,
    encrypt: bool,
    f: impl FnOnce(&mut Context) -> tss_esapi::Result<T>,
) -> tss_esapi::Result<T> {
    let session = ctx
        .execute_without_session(|ctx| {
            ctx.start_auth_session(
                Some(salt),
                None,
                None,
                SessionType::Hmac,
                SymmetricDefinition::AES_128_CFB,
                HashingAlgorithm::Sha256,
            )
        })?
        .ok_or(tss_esapi::Error::WrapperError(
            tss_esapi::WrapperErrorKind::WrongValueFromTpm,
        ))?;
    ctx.execute_with_temporary_object(SessionHandle::from(session).into(), |ctx, _| {
        let (attributes, mask) = SessionAttributesBuilder::new()
            .with_continue_session(true)
            .with_decrypt(decrypt)
            .with_encrypt(encrypt)
            .build();
        ctx.tr_sess_set_attributes(session, attributes, mask)?;
        ctx.execute_with_session(Some(session), f)
    })
}

impl Tpm {
    pub fn new(config: TctiNameConf) -> Result<Self> {
        let mut context = Context::new(config)?;
        // No secret input here. Owner/object auth is empty; startup never changes hierarchy auth.
        let root = context
            .execute_with_session(
                Some(tss_esapi::interface_types::session_handles::AuthSession::Password),
                |ctx| {
                    ctx.create_primary(
                        Hierarchy::Owner,
                        template(Kind::Root)?,
                        None,
                        None,
                        None,
                        None,
                    )
                },
            )?
            .key_handle;
        Ok(Self { context, root })
    }

    fn with_parent<T>(
        &mut self,
        record: &ParentRecord,
        hash: &[u8; 16],
        f: impl FnOnce(&mut Context, KeyHandle, KeyHandle) -> tss_esapi::Result<T>,
    ) -> tss_esapi::Result<T> {
        let root = self.root;
        protected(&mut self.context, root, false, false, |ctx| {
            let p = ctx.load(
                root,
                record.parent.private.clone(),
                record.parent.public.clone(),
            )?;
            ctx.execute_with_temporary_object(p.into(), |ctx, _| {
                ctx.tr_set_auth(p.into(), Auth::try_from(hash.as_slice())?)?;
                f(ctx, p, root)
            })
        })
    }

    pub fn provision(&mut self, hash: &[u8; 16], length: u8) -> Result<ParentRecord> {
        let mut master = Secret::from_exposed_secret([0u8; 64]);
        SysRng
            .try_fill_bytes(&mut *master)
            .map_err(|_| Error::Invalid("OS randomness unavailable"))?;
        let root = self.root;
        let p = protected(&mut self.context, root, true, true, |ctx| {
            ctx.create(
                root,
                template(Kind::Parent)?,
                Some(Auth::try_from(hash.as_slice())?),
                None,
                None,
                None,
            )
        })?;
        let s = protected(&mut self.context, root, false, false, |ctx| {
            let handle = ctx.load(root, p.out_private.clone(), p.out_public.clone())?;
            ctx.execute_with_temporary_object(handle.into(), |ctx, _| {
                ctx.tr_set_auth(handle.into(), Auth::try_from(hash.as_slice())?)?;
                protected(ctx, root, true, true, |ctx| {
                    ctx.create(
                        handle,
                        template(Kind::Check)?,
                        None,
                        Some(SensitiveData::try_from(master.as_slice())?),
                        None,
                        None,
                    )
                })
            })
        })?;
        let result = ParentRecord {
            parent: Blob {
                public: p.out_public,
                private: p.out_private,
            },
            check: Blob {
                public: s.out_public,
                private: s.out_private,
            },
            pin_length: length,
        };
        Ok(result)
    }

    pub fn verify(&mut self, record: &ParentRecord, hash: &[u8; 16]) -> Result<Secret<[u8; 64]>> {
        let bytes = self.with_parent(record, hash, |ctx, p, root| {
            let s = ctx.load(p, record.check.private.clone(), record.check.public.clone())?;
            ctx.execute_with_temporary_object(s.into(), |ctx, _| {
                protected(ctx, root, false, true, |ctx| ctx.unseal(s.into()))
            })
        })?;
        if bytes.value().len() != 64 {
            return Err(Error::Invalid("invalid sealed master length"));
        }
        let mut master = Secret::from_exposed_secret([0u8; 64]);
        master.copy_from_slice(bytes.value());
        Ok(master)
    }

    pub fn generate(&mut self, record: &ParentRecord, hash: &[u8; 16]) -> Result<Blob> {
        let k = self.with_parent(record, hash, |ctx, p, root| {
            protected(ctx, root, true, true, |ctx| {
                ctx.create(p, template(Kind::Signing)?, None, None, None, None)
            })
        })?;
        Ok(Blob {
            public: k.out_public,
            private: k.out_private,
        })
    }

    pub fn sign(
        &mut self,
        record: &ParentRecord,
        hash: &[u8; 16],
        key: &Blob,
        message: &[u8],
    ) -> Result<p256::ecdsa::Signature> {
        validate(&key.public, Kind::Signing)?;
        let digest: [u8; 32] = Sha256::digest(message).into();
        let signature = self.with_parent(record, hash, |ctx, p, _root| {
            let k = ctx.load(p, key.private.clone(), key.public.clone())?;
            ctx.execute_with_temporary_object(k.into(), |ctx, _| {
                let ticket = HashcheckTicket::try_from(tss_esapi::tss2_esys::TPMT_TK_HASHCHECK {
                    tag: StructureTag::Hashcheck.into(),
                    hierarchy: tss_esapi::handles::TpmHandle::from(Hierarchy::Null).into(),
                    digest: Default::default(),
                })?;
                ctx.sign(
                    k,
                    Digest::try_from(digest.as_slice())?,
                    SignatureScheme::EcDsa {
                        hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
                    },
                    ticket,
                )
            })
        })?;
        let Signature::EcDsa(s) = signature else {
            return Err(Error::Invalid("unexpected TPM signature"));
        };
        p256::ecdsa::Signature::from_scalars(
            coordinate(s.signature_r().value())?,
            coordinate(s.signature_s().value())?,
        )
        .map_err(|_| Error::Invalid("invalid TPM signature"))
    }

    pub fn change_pin(
        &mut self,
        record: &ParentRecord,
        old: &[u8; 16],
        new: &[u8; 16],
        length: u8,
    ) -> Result<ParentRecord> {
        let private = self.with_parent(record, old, |ctx, p, root| {
            protected(ctx, root, true, true, |ctx| {
                ctx.object_change_auth(p.into(), root.into(), Auth::try_from(new.as_slice())?)
            })
        })?;
        let mut next = record.clone();
        next.parent.private = private;
        next.pin_length = length;
        Ok(next)
    }
}
