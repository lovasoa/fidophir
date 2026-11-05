// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::tpm::{Kind, ParentRecord, fixture_blob};
use opensk::ctap::{cbor_read, cbor_write};
use sk_cbor::cbor_map;
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
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn parent() -> Vec<u8> {
    ParentRecord {
        parent: fixture_blob(Kind::Parent),
        check: fixture_blob(Kind::Check),
        pin_length: 4,
    }
    .encode()
    .unwrap()
}
fn record(i: u8) -> Vec<u8> {
    let mut bytes = Vec::new();
    cbor_write(
        sk_cbor::cbor_map! {
            0 => vec![i; 32], 2 => "example.com", 3 => vec![i; 16],
            4 => "Alice\nÉléonore\\ = []", 6 => 3, 7 => u64::MAX,
            8 => "alice", 9 => "", 10 => Vec::<u8>::new(), 11 => vec![42; 32],
            12 => sk_cbor::cbor_array![-7, fixture_blob(Kind::Signing).encode().unwrap()],
        },
        &mut bytes,
    )
    .unwrap();
    bytes
}
fn populate(store: &Store) {
    store.write(PARENT, &parent()).unwrap();
    store.write(1700, &record(1)).unwrap();
    store.write(1701, &record(2)).unwrap();
}

#[test]
fn readable_roundtrip_atomic_replace_delete_reopen_and_lock() {
    let root = Directory::new();
    let store = Store::open(&root.0).unwrap();
    assert!(Store::open(&root.0).is_err());
    populate(&store);
    let meta = root.path("v2/credentials/00000/metadata.ini");
    let text = fs::read_to_string(&meta).unwrap();
    assert!(text.contains("rp_id=example.com"));
    assert!(text.contains("creation_order=18446744073709551615"));
    assert_eq!(store.read(1700).unwrap(), Some(record(1)));
    assert!(store.write(1700, b"invalid replacement").is_err());
    assert_eq!(store.read(1700).unwrap(), Some(record(1)));
    assert!(!root.path("v2/credentials/.00000.pending").exists());
    assert_eq!(fs::metadata(&meta).unwrap().mode() & 0o777, 0o600);
    assert_eq!(
        fs::metadata(meta.parent().unwrap()).unwrap().mode() & 0o777,
        0o700
    );
    store.write(1700, &record(3)).unwrap();
    assert_eq!(store.read(1700).unwrap(), Some(record(3)));
    let changed = fs::read_to_string(&meta)
        .unwrap()
        .replace("user_name=alice", "user_name=bob");
    fs::write(&meta, changed).unwrap();
    let edited = opensk::ctap::data_formats::PublicKeyCredentialSource::try_from(
        cbor_read(&store.read(1700).unwrap().unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(edited.user_name.as_deref(), Some("bob"));
    drop(store);
    let store = Store::open(&root.0).unwrap();
    assert_eq!(store.free_credential_key().unwrap(), Some(1702));
    store.remove(1700).unwrap();
    store.remove(1700).unwrap();
    assert_eq!(store.free_credential_key().unwrap(), Some(1700));
    assert!(store.read(1700).unwrap().is_none());
}

#[test]
fn damaged_credential_is_skipped_reserved_and_repairable() {
    let root = Directory::new();
    let store = Store::open(&root.0).unwrap();
    populate(&store);
    let meta = root.path("v2/credentials/00000/metadata.ini");
    let original = fs::read(&meta).unwrap();
    for content in [
        b"broken [INI".as_slice(),
        b"[credential]\nformat_version=99\n",
    ] {
        fs::write(&meta, content).unwrap();
        assert!(store.read(1700).unwrap().is_none());
        assert_eq!(store.read(1701).unwrap(), Some(record(2)));
        assert_eq!(store.free_credential_key().unwrap(), Some(1702));
        assert!(store.write(1700, &record(3)).is_err());
    }
    drop(store);
    let store = Store::open(&root.0).unwrap(); // Corruption must not prevent startup.
    fs::write(&meta, original).unwrap();
    assert_eq!(store.read(1700).unwrap(), Some(record(1)));
    let blob = root.path("v2/credentials/00000/tpm-signing-blob.bin");
    fs::write(&blob, b"damaged").unwrap();
    assert!(store.read(1700).unwrap().is_none());
    assert_eq!(store.read(1701).unwrap(), Some(record(2)));
    store.remove(1700).unwrap();
    assert_eq!(store.free_credential_key().unwrap(), Some(1700));
}

#[test]
fn unsafe_credential_files_are_isolated_and_shared_state_errors_have_paths() {
    let root = Directory::new();
    let store = Store::open(&root.0).unwrap();
    populate(&store);
    let file = root.path("v2/credentials/00000/user-handle.bin");
    let original = fs::read(&file).unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(store.read(1700).unwrap().is_none());
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    let alias = root.path("alias");
    fs::hard_link(&file, &alias).unwrap();
    assert!(store.read(1700).unwrap().is_none());
    fs::remove_file(&alias).unwrap();
    fs::rename(&file, &alias).unwrap();
    symlink(&alias, &file).unwrap();
    assert!(store.read(1700).unwrap().is_none());
    fs::remove_file(&file).unwrap();
    assert!(store.read(1700).unwrap().is_none());
    assert_eq!(store.read(1701).unwrap(), Some(record(2)));
    // Never block on an unexpected FIFO.
    nix::unistd::mkfifo(
        &file,
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )
    .unwrap();
    assert!(store.read(1700).unwrap().is_none());
    fs::remove_file(&file).unwrap();
    fs::write(&alias, original).unwrap();
    fs::rename(&alias, &file).unwrap();
    assert_eq!(store.read(1700).unwrap(), Some(record(1)));
    let parent = root.path("v2/authenticator/tpm-parent.bin");
    let backup = fs::read(&parent).unwrap();
    fs::remove_file(&parent).unwrap();
    assert!(
        store
            .read(PARENT)
            .unwrap_err()
            .to_string()
            .contains("refusing to provision")
    );
    drop(store);
    assert!(
        Store::open(&root.0)
            .err()
            .unwrap()
            .to_string()
            .contains("tpm-parent.bin")
    );
    fs::write(&parent, b"damaged").unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(
        Store::open(&root.0)
            .err()
            .unwrap()
            .to_string()
            .contains("restore")
    );
    fs::write(&parent, backup).unwrap();
    assert!(Store::open(&root.0).is_ok());
}

#[test]
fn incomplete_initialization_can_be_reopened() {
    let root = Directory::new();
    DirBuilder::new()
        .mode(0o700)
        .create(root.path("v2"))
        .unwrap();
    let store = Store::open(&root.0).unwrap();
    assert!(root.path("v2/credentials").is_dir());
    assert!(root.path("v2/authenticator").is_dir());
    populate(&store);
    drop(store);
    let store = Store::open(&root.0).unwrap();
    assert_eq!(store.read(1700).unwrap(), Some(record(1)));
}

#[test]
fn capacity_and_interrupted_publication() {
    let root = Directory::new();
    let store = Store::open(&root.0).unwrap();
    store.write(PARENT, &parent()).unwrap();
    // Empty/damaged directories reserve slots without doing 300 durable writes.
    for key in CREDENTIALS {
        store.mkdir(&store.key_path(key).unwrap()).unwrap();
    }
    assert_eq!(store.free_credential_key().unwrap(), None);
    store.remove(1700).unwrap();
    store.write(1700, &record(1)).unwrap();
    let pending = root.path("v2/credentials/.00000.pending");
    store.mkdir(&pending).unwrap();
    store
        .write_file(&pending.join("metadata.ini"), b"partial")
        .unwrap();
    drop(store);
    let store = Store::open(&root.0).unwrap();
    assert!(!pending.exists());
    assert_eq!(store.read(1700).unwrap(), Some(record(1)));
    assert!(store.write(4096, b"invalid").is_err());
    assert!(store.write(100, &[0; MAX_VALUE + 1]).is_err());
    assert!(cbor_read(&store.read(1700).unwrap().unwrap()).is_ok());
}
