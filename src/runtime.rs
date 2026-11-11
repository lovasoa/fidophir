// SPDX-License-Identifier: Apache-2.0
//! Composition root. Build host services here, then inject them into OpenSK.
use crate::{Result, approval::Approval, backend::Backend, env::LinuxEnv, io::SharedIo};
use std::path::PathBuf;

#[cfg(not(feature = "systemd-tests"))]
const SYSTEM_TPM: &str = "device:/dev/tpmrm0";
#[cfg(feature = "systemd-tests")]
const SYSTEM_TPM: &str = "tabrmd:bus_name=com.intel.tss2.Tabrmd,bus_type=system";

pub fn system(root: PathBuf, io: SharedIo, uid: u32) -> Result<LinuxEnv> {
    let backend = Backend::connect(
        root,
        SYSTEM_TPM.parse()?,
        io.clone(),
        &crate::opensk_adapter::credential::OpenSkCodec,
    )?;
    let approval = Approval::new(io.clone(), uid)?;
    LinuxEnv::build(backend, approval, io)
}

#[cfg(feature = "integration-tests")]
pub fn simulator(
    root: PathBuf,
    config: &str,
    io: SharedIo,
    decision: Option<bool>,
) -> Result<LinuxEnv> {
    if !config.starts_with("swtpm:host=127.0.0.1,port=") {
        return Err(crate::Error::Invalid("test requires a loopback simulator"));
    }
    let backend = Backend::connect(
        root,
        config.parse()?,
        io.clone(),
        &crate::opensk_adapter::credential::OpenSkCodec,
    )?;
    let approval = match decision {
        Some(allow) => Approval::fixed(io.clone(), allow),
        None => Approval::new(io.clone(), nix::unistd::geteuid().as_raw())?,
    };
    LinuxEnv::build(backend, approval, io)
}
