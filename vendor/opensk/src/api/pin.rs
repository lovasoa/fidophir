//! Hardware authorization boundary. The protocol still owns PIN parsing and retries.
use crate::ctap::status_code::CtapResult;

pub trait PinAuthority {
    fn is_set(&self) -> CtapResult<bool>;
    fn install(&mut self, hash: &[u8; 16], length: u8) -> CtapResult<()>;
    fn verify(&mut self, hash: &[u8; 16]) -> CtapResult<bool>;
    fn replace_verified(&mut self, hash: &[u8; 16], length: u8) -> CtapResult<()>;
    fn matches_verified(&self, hash: &[u8; 16]) -> bool;
    fn clear(&mut self);
}
