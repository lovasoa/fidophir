// SPDX-License-Identifier: Apache-2.0
#[cfg(test)]
extern crate alloc;
pub mod approval;
pub mod backend;
pub mod env;
pub mod io;
pub mod state;
pub mod tpm;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Tpm(tss_esapi::Error),
    Invalid(&'static str),
    Desktop(glib::Error),
    State {
        path: std::path::PathBuf,
        reason: String,
    },
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<tss_esapi::Error> for Error {
    fn from(e: tss_esapi::Error) -> Self {
        Self::Tpm(e)
    }
}
impl From<glib::Error> for Error {
    fn from(e: glib::Error) -> Self {
        Self::Desktop(e)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Error text never includes credential bytes, authorization or RP information.
        match self {
            Self::Io(e) => write!(f, "filesystem/transport error: {}", e.kind()),
            Self::Tpm(e) => write!(f, "TPM error: {e}"),
            Self::Invalid(e) => f.write_str(e),
            Self::Desktop(_) => f.write_str("desktop authorization failed"),
            Self::State { path, reason } => write!(f, "state {path:?}: {reason}"),
        }
    }
}
impl std::error::Error for Error {}
