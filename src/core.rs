// SPDX-License-Identifier: Apache-2.0
//! Protocol-independent host operation results and secret storage.
/// Heap-resident secrets are erased before their allocation is released.
#[derive(Clone)]
pub struct Secret<T: zeroize::Zeroize>(Box<T>);
impl<T: zeroize::Zeroize> Secret<T> {
    pub fn new(value: T) -> Self {
        Self(Box::new(value))
    }
}
impl<T: zeroize::Zeroize> std::ops::Deref for Secret<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}
impl<T: zeroize::Zeroize> std::ops::DerefMut for Secret<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}
impl<T: zeroize::Zeroize> Drop for Secret<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Services pumped while waiting for the serialized TPM worker.
pub trait HostServices {
    fn cancelled(&self) -> bool;
    fn service(&self) -> crate::Result<()>;
}

pub fn boot_ms() -> u64 {
    let t = nix::time::clock_gettime(nix::time::ClockId::CLOCK_BOOTTIME)
        .expect("CLOCK_BOOTTIME unavailable");
    (t.tv_sec() as u64).saturating_mul(1000) + t.tv_nsec() as u64 / 1_000_000
}
pub type BackendResult<T> = Result<T, BackendError>;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendError {
    Cancelled,
    PinBlocked,
    Hardware,
    Internal,
    AuthorizationRequired,
    PinNotSet,
}
