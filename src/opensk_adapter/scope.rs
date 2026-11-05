// SPDX-License-Identifier: Apache-2.0
//! Instance routing for OpenSK crypto traits whose methods have no `Env` parameter.
//!
//! This scope confers no authorization: `Backend` still checks its own PIN access.
//! It only identifies the instance executing this synchronous OpenSK command.
use crate::backend::{Backend, adapter_invariant};
use opensk::api::crypto::{hkdf256::Hkdf256, rust_crypto::SoftwareHkdf256};
use std::cell::RefCell;

thread_local! {
    static ACTIVE_BACKEND: RefCell<Option<Backend>> = const { RefCell::new(None) };
}

struct BackendScope;
impl Drop for BackendScope {
    fn drop(&mut self) {
        ACTIVE_BACKEND.with(|active| active.borrow_mut().take());
    }
}

/// Reject nested dispatch rather than letting callbacks use the wrong instance.
pub(crate) fn with_backend<T>(backend: &Backend, dispatch: impl FnOnce() -> T) -> T {
    ACTIVE_BACKEND.with(|active| {
        let mut active = active.borrow_mut();
        if active.is_some() {
            adapter_invariant("dispatch-scope", "nested-dispatch");
        }
        *active = Some(backend.clone());
    });
    let _scope = BackendScope;
    dispatch()
}

pub(crate) fn current_backend() -> Backend {
    // Release the TLS borrow before TPM work: it pumps desktop callbacks.
    ACTIVE_BACKEND.with(|active| {
        active
            .borrow()
            .clone()
            .unwrap_or_else(|| adapter_invariant("dispatch-scope", "missing-backend"))
    })
}

/// Transparent HKDF with request-local observation of the genuine ClientPIN key.
pub struct PinProtocolHkdf256;
impl Hkdf256 for PinProtocolHkdf256 {
    fn hkdf_256(ikm: &[u8], salt: &[u8; 32], info: &[u8], output: &mut [u8; 32]) {
        SoftwareHkdf256::hkdf_256(ikm, salt, info, output);
        // Preserve HKDF exactly. This pinned label identifies the v2 PIN AES key;
        // Backend captures it only while the current PIN request awaits a key.
        if salt == &[0; 32] && info == b"CTAP2 AES key" {
            current_backend().observe_pin_aes_key(output);
        }
    }
}
