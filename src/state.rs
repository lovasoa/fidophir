// SPDX-License-Identifier: Apache-2.0
//! One durable file per OpenSK record. No credential cache or secondary index.
use crate::{Error, Result};
use glib::FileSetContentsFlags as Flags;
use nix::fcntl::{Flock, FlockArg};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

pub const PARENT: usize = 65536;
pub const MAX_VALUE: usize = 4096;
const MAX_RECORDS: usize = 128;

pub struct Store {
    path: PathBuf,
    directory: Flock<File>,
    uid: u32,
}

fn key_name(key: usize) -> Result<String> {
    if key > 4095 && key != PARENT {
        return Err(Error::Invalid("invalid storage key"));
    }
    Ok(format!("{key:05}"))
}

fn parse_name(name: &str) -> Option<usize> {
    if name.len() != 5 || !name.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let key = name.parse().ok()?;
    key_name(key).ok().filter(|n| n == name).map(|_| key)
}

fn check(meta: &fs::Metadata, uid: u32, directory: bool) -> Result<()> {
    let mode = if directory { 0o700 } else { 0o600 };
    if meta.uid() != uid
        || meta.mode() & 0o7777 != mode
        || (directory && !meta.is_dir())
        || (!directory && (!meta.is_file() || meta.nlink() != 1 || meta.len() > MAX_VALUE as u64))
    {
        return Err(Error::Invalid("unsafe state ownership, type, mode or size"));
    }
    Ok(())
}

impl Store {
    pub fn open(root: &Path) -> Result<Self> {
        let uid = nix::unistd::geteuid().as_raw();
        check(&fs::symlink_metadata(root)?, uid, true)?;
        for item in fs::read_dir(root)? {
            if item?.file_name() != "v1" {
                return Err(Error::Invalid("unknown state layout"));
            }
        }
        let path = root.join("v1");
        match DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => File::open(root)?.sync_all()?,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
            Err(e) => return Err(e.into()),
        }
        check(&fs::symlink_metadata(&path)?, uid, true)?;
        let fd = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW)
            .open(&path)?;
        let directory = Flock::lock(fd, FlockArg::LockExclusiveNonblock)
            .map_err(|(_, _)| Error::Invalid("state directory is already locked"))?;
        let store = Self {
            path,
            directory,
            uid,
        };
        let mut dirty = false;
        for entry in fs::read_dir(&store.path)? {
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| Error::Invalid("invalid state filename"))?;
            if parse_name(&name).is_some() {
                continue;
            }
            let residue = name.split_once('.').is_some_and(|(base, suffix)| {
                parse_name(base).is_some()
                    && suffix.len() == 6
                    && suffix.bytes().all(|b| b.is_ascii_alphanumeric())
            });
            if !residue {
                return Err(Error::Invalid("unexpected state entry"));
            }
            check(&fs::symlink_metadata(entry.path())?, uid, false)?;
            fs::remove_file(entry.path())?;
            dirty = true;
        }
        if dirty {
            store.directory.sync_all()?;
        }
        store.list()?;
        // A hardware-backed Linux instance does not expose factory reset.
        if store.read(20)?.is_some() {
            return Err(Error::Invalid("unexpected reset marker"));
        }
        Ok(store)
    }

    pub fn read(&self, key: usize) -> Result<Option<Vec<u8>>> {
        let path = self.path.join(key_name(key)?);
        let fd = match OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(path)
        {
            Ok(fd) => fd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        check(&fd.metadata()?, self.uid, false)?;
        let mut bytes = Vec::new();
        fd.take((MAX_VALUE + 1) as u64).read_to_end(&mut bytes)?;
        if bytes.len() > MAX_VALUE {
            return Err(Error::Invalid("oversized state record"));
        }
        Ok(Some(bytes))
    }

    pub fn list(&self) -> Result<Vec<usize>> {
        let mut keys = Vec::new();
        for entry in fs::read_dir(&self.path)? {
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| Error::Invalid("invalid state filename"))?;
            let key = parse_name(&name).ok_or(Error::Invalid("unexpected state entry"))?;
            check(&fs::symlink_metadata(entry.path())?, self.uid, false)?;
            keys.push(key);
            if keys.len() > MAX_RECORDS {
                return Err(Error::Invalid("too many state records"));
            }
        }
        keys.sort_unstable();
        Ok(keys)
    }

    pub fn write(&self, key: usize, bytes: &[u8]) -> Result<()> {
        if bytes.len() > MAX_VALUE {
            return Err(Error::Invalid("oversized state record"));
        }
        let exists = self.read(key)?.is_some();
        if !exists && self.list()?.len() >= MAX_RECORDS {
            return Err(Error::Invalid("state store is full"));
        }
        glib::file_set_contents_full(
            self.path.join(key_name(key)?),
            bytes,
            Flags::CONSISTENT | Flags::DURABLE,
            0o600,
        )?;
        Ok(())
    }

    pub fn remove(&self, key: usize) -> Result<()> {
        if self.read(key)?.is_some() {
            fs::remove_file(self.path.join(key_name(key)?))?;
            self.directory.sync_all()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "fidophir-store-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn durable_replace_delete_reopen_and_exclusive_lock() {
        let root = Directory::new();
        let store = Store::open(&root.0).unwrap();
        assert!(Store::open(&root.0).is_err());
        store.write(1700, b"first").unwrap();
        store.write(1700, b"replacement").unwrap();
        assert_eq!(store.list().unwrap(), vec![1700]);
        assert_eq!(
            fs::metadata(root.0.join("v1/01700")).unwrap().mode() & 0o777,
            0o600
        );
        drop(store);
        let store = Store::open(&root.0).unwrap();
        assert_eq!(store.read(1700).unwrap().unwrap(), b"replacement");
        store.remove(1700).unwrap();
        store.remove(1700).unwrap();
        drop(store);
        assert!(Store::open(&root.0).unwrap().list().unwrap().is_empty());
    }

    #[test]
    fn reject_links_permissions_and_noncanonical_names() {
        let root = Directory::new();
        let store = Store::open(&root.0).unwrap();
        store.write(1700, b"secret").unwrap();
        let file = root.0.join("v1/01700");
        let alias = root.0.join("v1/01701");
        symlink(&file, &alias).unwrap();
        assert!(store.read(1701).is_err());
        assert!(store.list().is_err());
        fs::remove_file(&alias).unwrap();
        fs::hard_link(&file, &alias).unwrap();
        assert!(store.read(1700).is_err());
        assert!(store.write(1701, b"must refuse").is_err());
        fs::remove_file(&alias).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(store.read(1700).is_err());
        drop(store);
        assert!(Store::open(&root.0).is_err());
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        fs::rename(file, root.0.join("v1/1700")).unwrap();
        assert!(Store::open(&root.0).is_err());
    }

    #[test]
    fn bounded_records_and_validated_crash_residue() {
        let root = Directory::new();
        let store = Store::open(&root.0).unwrap();
        assert!(store.write(4096, b"invalid key").is_err());
        assert!(store.write(0, &[0; MAX_VALUE + 1]).is_err());
        for key in 100..100 + MAX_RECORDS {
            store.write(key, b"record").unwrap();
        }
        assert!(store.write(PARENT, b"full").is_err());
        store.write(100, b"replacement when full").unwrap();
        store.remove(100).unwrap();
        store.write(PARENT, b"parent").unwrap();
        drop(store);
        let residue = root.0.join("v1/00100.A1b2C3");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&residue)
            .unwrap();
        let store = Store::open(&root.0).unwrap();
        assert!(!residue.exists());
        drop(store);
        symlink(root.0.join("v1/65536"), residue).unwrap();
        assert!(Store::open(&root.0).is_err());
    }
}
