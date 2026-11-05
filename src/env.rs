// SPDX-License-Identifier: Apache-2.0
use crate::{
    Error, Result,
    approval::Approval,
    backend::{Backend, TpmEcdsa},
    io::{SharedIo, boot_ms, dispatch_desktop},
    opensk_adapter::PinProtocolHkdf256,
};
use opensk::{
    api::{
        clock::Clock,
        connection::{HidConnection, RecvStatus, UsbEndpoint},
        crypto::{Crypto, rust_crypto::*},
        customization::{CustomizationImpl, DEFAULT_CUSTOMIZATION},
        rng::rand_core::{CryptoRng, Error as RngError, RngCore},
    },
    ctap::{
        data_formats::CredentialProtectionPolicy,
        status_code::{Ctap2StatusCode as Status, CtapResult},
    },
    env::Env,
};
use rand::{
    Rng, SeedableRng,
    rngs::{StdRng, SysRng},
};
use std::{path::PathBuf, time::Duration};

// OpenSK 0.1.0 uses rand_core 0.6. Adapt its traits to our OS-seeded generator.
pub struct HostRng(StdRng);
impl RngCore for HostRng {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }
    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }
    fn fill_bytes(&mut self, out: &mut [u8]) {
        self.0.fill_bytes(out);
    }
    fn try_fill_bytes(&mut self, out: &mut [u8]) -> std::result::Result<(), RngError> {
        self.fill_bytes(out);
        Ok(())
    }
}
impl CryptoRng for HostRng {}
impl opensk::api::rng::Rng for HostRng {}

pub struct HostCrypto;
impl Crypto for HostCrypto {
    type Aes256 = SoftwareAes256;
    type Ecdh = SoftwareEcdh;
    type Ecdsa = TpmEcdsa;
    type Sha256 = SoftwareSha256;
    type Hmac256 = SoftwareHmac256;
    type Hkdf256 = PinProtocolHkdf256;
}

pub struct HostClock;
impl Clock for HostClock {
    type Timer = u64;
    fn make_timer(&mut self, milliseconds: usize) -> u64 {
        boot_ms().saturating_add(milliseconds as u64)
    }
    fn is_elapsed(&mut self, deadline: &u64) -> bool {
        boot_ms() >= *deadline
    }
}

pub struct Sink;
impl std::fmt::Write for Sink {
    fn write_str(&mut self, _: &str) -> std::fmt::Result {
        Ok(())
    }
}

pub struct Connection(pub SharedIo);
impl HidConnection for Connection {
    fn send(&mut self, frame: &[u8; 64], _: UsbEndpoint) -> CtapResult<()> {
        self.0
            .borrow_mut()
            .send(frame)
            .map_err(|_| Status::CTAP2_ERR_VENDOR_HARDWARE_FAILURE)
    }
    fn recv(&mut self, frame: &mut [u8; 64], timeout_ms: usize) -> CtapResult<RecvStatus> {
        let end = boot_ms().saturating_add(timeout_ms as u64);
        loop {
            if let Some(input) = self
                .0
                .borrow_mut()
                .receive()
                .map_err(|_| Status::CTAP2_ERR_VENDOR_HARDWARE_FAILURE)?
            {
                *frame = input;
                return Ok(RecvStatus::Received(UsbEndpoint::MainHid));
            }
            if boot_ms() >= end {
                return Ok(RecvStatus::Timeout);
            }
            dispatch_desktop();
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

pub struct LinuxEnv {
    rng: HostRng,
    pub backend: Backend,
    approval: Approval,
    clock: HostClock,
    connection: Connection,
    profile: CustomizationImpl,
}

impl LinuxEnv {
    pub fn new(root: PathBuf, io: SharedIo, uid: u32) -> Result<Self> {
        let backend = Backend::new(root, io.clone())?;
        let approval = Approval::new(io.clone(), uid)?;
        Self::build(backend, approval, io)
    }
    #[cfg(any(test, feature = "integration-tests"))]
    pub fn for_test(root: PathBuf, config: &str, io: SharedIo, allow: bool) -> Result<Self> {
        let backend = Backend::for_test(root, config, io.clone())?;
        let approval = Approval::for_test(io.clone(), allow);
        Self::build(backend, approval, io)
    }
    #[cfg(feature = "integration-tests")]
    pub fn for_test_native(root: PathBuf, config: &str, io: SharedIo) -> Result<Self> {
        let backend = Backend::for_test(root, config, io.clone())?;
        let approval = Approval::new(io.clone(), nix::unistd::geteuid().as_raw())?;
        Self::build(backend, approval, io)
    }
    fn build(backend: Backend, approval: Approval, io: SharedIo) -> Result<Self> {
        let rng = HostRng(
            StdRng::try_from_rng(&mut SysRng)
                .map_err(|_| Error::Invalid("OS randomness unavailable"))?,
        );
        let profile = CustomizationImpl {
            allows_pin_protocol_v1: false,
            enforce_always_uv: true,
            default_min_pin_length: 4,
            max_supported_resident_keys: opensk::api::persist::keys::CREDENTIALS.len(),
            use_signature_counter: false,
            default_cred_protect: Some(CredentialProtectionPolicy::UserVerificationRequired),
            ..DEFAULT_CUSTOMIZATION
        };
        Ok(Self {
            rng,
            backend,
            approval,
            clock: HostClock,
            connection: Connection(io),
            profile,
        })
    }
    pub(crate) fn set_approval_context(
        &mut self,
        operation: Option<&'static str>,
        rp: Option<&str>,
    ) {
        self.approval.set_context(operation, rp);
    }

    pub(crate) fn command_was_cancelled(&self) -> bool {
        self.connection.0.borrow().cancelled()
    }
}

impl Env for LinuxEnv {
    type Rng = HostRng;
    type UserPresence = Approval;
    type Persist = Backend;
    type KeyStore = Backend;
    type Clock = HostClock;
    type Crypto = HostCrypto;
    type Write = Sink;
    type Customization = CustomizationImpl;
    type HidConnection = Connection;
    fn rng(&mut self) -> &mut HostRng {
        &mut self.rng
    }
    fn user_presence(&mut self) -> &mut Approval {
        &mut self.approval
    }
    fn persist(&mut self) -> &mut Backend {
        &mut self.backend
    }
    fn key_store(&mut self) -> &mut Backend {
        &mut self.backend
    }
    fn clock(&mut self) -> &mut HostClock {
        &mut self.clock
    }
    fn customization(&self) -> &CustomizationImpl {
        &self.profile
    }
    fn hid_connection(&mut self) -> &mut Connection {
        &mut self.connection
    }
    fn write(&mut self) -> Sink {
        Sink
    }
    fn boots_after_soft_reset(&self) -> bool {
        true
    }
}
