// SPDX-License-Identifier: Apache-2.0
//! Bounded, readable state. No credential cache or secondary index.
mod credential;

use crate::{Error, Result};
use glib::FileSetContentsFlags as Flags;
use opensk::api::persist::keys::CREDENTIALS;
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};

pub const PARENT: usize = 65536;
pub const MAX_VALUE: usize = 4096;
const README: &str = include_str!("state/README.txt");
const RECORDS: &[(usize, &str)] = &[
    (1, "attestation-private-key.bin"),
    (2, "attestation-certificate.bin"),
    (3, "aaguid.bin"),
    (4, "attestation-id.bin"),
    (20, "reset-marker.bin"),
    (2000, "large-blob-0.bin"),
    (2001, "large-blob-1.bin"),
    (2002, "large-blob-2.bin"),
    (2003, "large-blob-3.bin"),
    (2038, "always-uv.flag"),
    (2040, "force-pin-change.flag"),
    (2042, "min-pin-length-rp-ids.bin"),
    (2043, "min-pin-length.bin"),
    (2044, "pin-retries.bin"),
    (2045, "pin-properties.bin"),
    (2046, "key-store.bin"),
    (2047, "signature-counter.bin"),
    (PARENT, "tpm-parent.bin"),
];

pub struct Store {
    path: PathBuf,
    _directory: File,
    uid: u32,
    reported: RefCell<BTreeSet<usize>>,
}

fn problem(path: &Path, reason: impl Into<String>) -> Error {
    Error::State {
        path: path.to_owned(),
        reason: reason.into(),
    }
}
fn io_at<T>(path: &Path, result: std::io::Result<T>) -> Result<T> {
    result.map_err(|e| problem(path, e.to_string()))
}
fn present(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(problem(path, e.to_string())),
    }
}
fn check_directory(path: &Path, uid: u32) -> Result<()> {
    let meta = io_at(path, fs::symlink_metadata(path))?;
    if !meta.is_dir() || meta.uid() != uid || meta.mode() & 0o7777 != 0o700 {
        return Err(problem(
            path,
            format!("expected directory owned by UID {uid}, mode 0700"),
        ));
    }
    Ok(())
}
fn sync_directory(path: &Path) -> Result<()> {
    io_at(path, File::open(path).and_then(|file| file.sync_all()))
}
fn lock(path: &Path, uid: u32) -> Result<File> {
    check_directory(path, uid)?;
    let fd = io_at(
        path,
        OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW)
            .open(path),
    )?;
    fd.try_lock().map_err(|e| match e {
        std::fs::TryLockError::WouldBlock => problem(
            path,
            "state directory is already locked; stop the other daemon",
        ),
        std::fs::TryLockError::Error(e) => problem(path, e.to_string()),
    })?;
    Ok(fd)
}
use std::os::unix::fs::OpenOptionsExt;

fn number(name: &str) -> Option<usize> {
    (name.len() == 5 && name.bytes().all(|b| b.is_ascii_digit()))
        .then(|| name.parse().ok())
        .flatten()
}
fn record_name(key: usize) -> Result<String> {
    if key > 4095 && key != PARENT {
        return Err(Error::Invalid("invalid storage key"));
    }
    Ok(RECORDS
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, n)| n.to_string())
        .unwrap_or_else(|| format!("record-{key:05}.bin")))
}
fn record_key(name: &str) -> Option<usize> {
    RECORDS
        .iter()
        .find(|(_, n)| *n == name)
        .map(|(k, _)| *k)
        .or_else(|| {
            let key = number(name.strip_prefix("record-")?.strip_suffix(".bin")?)?;
            (key <= 4095 && !CREDENTIALS.contains(&key) && record_name(key).ok()?.as_str() == name)
                .then_some(key)
        })
}

impl Store {
    pub fn open(root: &Path) -> Result<Self> {
        let uid = nix::unistd::geteuid().as_raw();
        let store = Self {
            path: root.join("v2"),
            _directory: lock(root, uid)?,
            uid,
            reported: RefCell::new(BTreeSet::new()),
        };
        for path in [
            store.path.clone(),
            store.path.join("credentials"),
            store.path.join("authenticator"),
        ] {
            match DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => sync_directory(path.parent().unwrap())?,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    store.check_dir(&path)?
                }
                Err(e) => return Err(problem(&path, e.to_string())),
            }
        }
        let readme = store.path.join("README.txt");
        if !present(&readme)? {
            store.write_file(&readme, README.as_bytes())?;
        }
        // Unpublished directories are created only by us. An interrupted exchange
        // leaves the previous complete credential here, so removal is safe.
        for entry in io_at(&store.path, fs::read_dir(store.path.join("credentials")))? {
            let entry = entry?;
            let name = entry.file_name();
            if name
                .to_str()
                .and_then(|s| s.strip_prefix('.'))
                .and_then(|s| s.strip_suffix(".pending"))
                .and_then(number)
                .is_some_and(|n| n < CREDENTIALS.len())
            {
                store.check_dir(&entry.path())?;
                io_at(&entry.path(), fs::remove_dir_all(entry.path()))?;
            }
        }
        if store.read(20)?.is_some() {
            return Err(problem(
                &store.path,
                "unexpected reset marker; restore a consistent backup",
            ));
        }
        store.read(PARENT)?;
        // Diagnose corrupt credentials at startup without disabling healthy ones.
        for key in store.list()? {
            if CREDENTIALS.contains(&key) {
                store.read(key)?;
            }
        }
        Ok(store)
    }

    fn mkdir(&self, path: &Path) -> Result<()> {
        io_at(path, DirBuilder::new().mode(0o700).create(path))
    }
    fn check_dir(&self, path: &Path) -> Result<()> {
        check_directory(path, self.uid)
    }
    fn read_file(&self, path: &Path) -> Result<Option<Vec<u8>>> {
        let fd = match OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(path)
        {
            Ok(fd) => fd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(problem(path, e.to_string())),
        };
        let meta = io_at(path, fd.metadata())?;
        if !meta.is_file()
            || meta.uid() != self.uid
            || meta.mode() & 0o7777 != 0o600
            || meta.nlink() != 1
            || meta.len() > MAX_VALUE as u64
        {
            return Err(problem(
                path,
                format!(
                    "expected regular file owned by UID {}, mode 0600, one link, at most 4096 bytes",
                    self.uid
                ),
            ));
        }
        let mut bytes = Vec::new();
        io_at(
            path,
            fd.take((MAX_VALUE + 1) as u64).read_to_end(&mut bytes),
        )?;
        if bytes.len() > MAX_VALUE {
            return Err(problem(path, "record exceeds 4096 bytes"));
        }
        Ok(Some(bytes))
    }
    fn write_file(&self, path: &Path, bytes: &[u8]) -> Result<()> {
        if bytes.len() > MAX_VALUE {
            return Err(problem(path, "record exceeds 4096 bytes"));
        }
        self.read_file(path)?;
        glib::file_set_contents_full(path, bytes, Flags::CONSISTENT | Flags::DURABLE, 0o600)
            .map_err(|_| {
                problem(
                    path,
                    "atomic durable write failed; check free space and permissions",
                )
            })
    }
    fn key_path(&self, key: usize) -> Result<PathBuf> {
        if CREDENTIALS.contains(&key) {
            self.check_dir(&self.path.join("credentials"))?;
            Ok(self
                .path
                .join("credentials")
                .join(format!("{:05}", key - CREDENTIALS.start)))
        } else {
            Ok(self.path.join("authenticator").join(record_name(key)?))
        }
    }
    pub fn read(&self, key: usize) -> Result<Option<Vec<u8>>> {
        let path = self.key_path(key)?;
        if CREDENTIALS.contains(&key) {
            if fs::symlink_metadata(&path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
            {
                return Ok(None);
            }
            return match credential::read(self, &path) {
                Ok(bytes) => {
                    self.reported.borrow_mut().remove(&key);
                    Ok(Some(bytes))
                }
                Err(error) => {
                    if self.reported.borrow_mut().insert(key) {
                        eprintln!("fidophir: skipping credential: {error}");
                    }
                    Ok(None)
                }
            };
        }
        self.check_dir(&self.path.join("authenticator"))?;
        let bytes = self.read_file(&path)?;
        if key == PARENT {
            match &bytes {
                Some(bytes) => {
                    crate::tpm::ParentRecord::decode(bytes).map_err(|_| {
                        problem(
                            &path,
                            "invalid shared Trusted Platform Module parent; restore this file from a matching backup",
                        )
                    })?;
                }
                None if self
                    .list()?
                    .into_iter()
                    .any(|key| CREDENTIALS.contains(&key)) =>
                {
                    return Err(problem(
                        &path,
                        "shared Trusted Platform Module parent is missing while credentials exist; restore it from backup; refusing to provision a replacement",
                    ));
                }
                None => (),
            }
        }
        Ok(bytes)
    }
    pub fn list(&self) -> Result<Vec<usize>> {
        let mut keys = Vec::new();
        for (subdir, credentials) in [("credentials", true), ("authenticator", false)] {
            let path = self.path.join(subdir);
            self.check_dir(&path)?;
            for entry in io_at(&path, fs::read_dir(&path))? {
                let entry = entry?;
                let name = entry.file_name();
                let name = name.to_str().unwrap_or("");
                let key = if credentials {
                    number(name)
                        .filter(|n| *n < CREDENTIALS.len())
                        .map(|n| n + CREDENTIALS.start)
                } else {
                    record_key(name)
                };
                if let Some(key) = key {
                    keys.push(key);
                }
                // Unrecognized files (editor backups, notes, interrupted writes)
                // are never used as authenticator state.
            }
        }
        keys.sort_unstable();
        Ok(keys)
    }
    pub fn free_credential_key(&self) -> Result<Option<usize>> {
        self.check_dir(&self.path.join("credentials"))?;
        for key in CREDENTIALS {
            match fs::symlink_metadata(self.key_path(key)?) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Some(key)),
                Err(e) => return Err(e.into()),
                Ok(_) => (), // A damaged credential still owns its slot.
            }
        }
        Ok(None)
    }
    pub fn write(&self, key: usize, bytes: &[u8]) -> Result<()> {
        let path = self.key_path(key)?;
        if !CREDENTIALS.contains(&key) {
            self.check_dir(&self.path.join("authenticator"))?;
            return self.write_file(&path, bytes);
        }
        let parent = self.path.join("credentials");
        self.check_dir(&parent)?;
        let exists = fs::symlink_metadata(&path).is_ok();
        if exists {
            credential::read(self, &path)?;
        }
        let staging = parent.join(format!(".{:05}.pending", key - CREDENTIALS.start));
        self.mkdir(&staging)?;
        let publish = (|| {
            credential::write(self, &staging, bytes)?;
            // Validate the complete new credential before publishing it.
            credential::read(self, &staging)?;
            sync_directory(&staging)?;
            if exists {
                use std::os::unix::ffi::OsStrExt;
                let a = std::ffi::CString::new(staging.as_os_str().as_bytes()).unwrap();
                let b = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
                let rc = unsafe {
                    nix::libc::renameat2(
                        nix::libc::AT_FDCWD,
                        a.as_ptr(),
                        nix::libc::AT_FDCWD,
                        b.as_ptr(),
                        nix::libc::RENAME_EXCHANGE,
                    )
                };
                if rc != 0 {
                    return Err(problem(&path, std::io::Error::last_os_error().to_string()));
                }
            } else {
                io_at(&path, fs::rename(&staging, &path))?;
            }
            sync_directory(&parent)
        })();
        // On failure, leave the old published directory intact. After an
        // exchange this removes only the old version, never the new one.
        if staging.exists() {
            io_at(&staging, fs::remove_dir_all(&staging))?;
        }
        publish
    }
    pub fn remove(&self, key: usize) -> Result<()> {
        let path = self.key_path(key)?;
        let parent = path.parent().unwrap();
        self.check_dir(parent)?;
        if fs::symlink_metadata(&path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) {
            return Ok(());
        }
        if CREDENTIALS.contains(&key) {
            self.check_dir(&path)?;
            io_at(&path, fs::remove_dir_all(&path))?;
        } else {
            self.read_file(&path)?;
            io_at(&path, fs::remove_file(&path))?;
        }
        sync_directory(parent)
    }
}

#[cfg(test)]
mod tests;
