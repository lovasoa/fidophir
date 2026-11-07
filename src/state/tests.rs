// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::tpm::{Kind, ParentRecord, fixture_blob};
use opensk::ctap::{cbor_read, cbor_write};
use sk_cbor::cbor_map;
use std::os::unix::fs::PermissionsExt;
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
fn damaged_credentials_are_parked_without_overwriting_and_can_be_restored() {
    let root = Directory::new();
    let store = Store::open(&root.0).unwrap();
    populate(&store);
    let slot = root.path("v2/credentials/00000");
    let original = fs::read(slot.join("metadata.ini")).unwrap();
    fs::write(slot.join("metadata.ini"), b"broken [INI").unwrap();
    assert!(store.read(1700).unwrap().is_none());
    let parked = root.path("v2/credentials/00000.damaged-1");
    assert!(parked.is_dir());
    assert_eq!(store.free_credential_key().unwrap(), Some(1700));
    assert_eq!(store.read(1701).unwrap(), Some(record(2)));
    store.write(1700, &record(3)).unwrap();
    fs::write(slot.join("metadata.ini"), b"broken again").unwrap();
    assert!(store.read(1700).unwrap().is_none());
    assert!(root.path("v2/credentials/00000.damaged-2").is_dir());
    assert_eq!(
        fs::read(parked.join("metadata.ini")).unwrap(),
        b"broken [INI"
    );
    fs::write(parked.join("metadata.ini"), original).unwrap();
    fs::rename(&parked, &slot).unwrap();
    assert_eq!(store.read(1700).unwrap(), Some(record(1)));
    drop(store);
    let store = Store::open(&root.0).unwrap();
    assert_eq!(store.read(1700).unwrap(), Some(record(1)));
}

#[test]
fn filesystem_errors_do_not_park_credentials_and_parked_entries_protect_parent() {
    let root = Directory::new();
    let store = Store::open(&root.0).unwrap();
    populate(&store);
    let slot = root.path("v2/credentials/00000");
    let file = slot.join("user-handle.bin");
    fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(store.read(1700).is_err());
    assert!(slot.is_dir());
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(slot.join("metadata.ini"), b"broken [INI").unwrap();
    assert!(store.read(1700).unwrap().is_none());
    store.remove(1701).unwrap();
    let parent = root.path("v2/authenticator/tpm-parent.bin");
    fs::remove_file(parent).unwrap();
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
            .contains("refusing to provision")
    );
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
fn startup_parks_invalid_credentials_and_updates_old_recovery_instructions() {
    let root = Directory::new();
    let store = Store::open(&root.0).unwrap();
    populate(&store);
    fs::write(root.path("v2/credentials/00000/metadata.ini"), b"[broken").unwrap();
    let readme = root.path("v2/README.txt");
    fs::write(&readme, "Local notes\nDamaged credentials are skipped, with the failing path reported in the journal.\nTheir slots stay reserved: new registrations never overwrite them. Restore the\nfiles with correct ownership/permissions, or remove the whole directory. No\ncredential cache needs rebuilding. Unrecognized filenames are ignored.\n").unwrap();
    drop(store);
    let store = Store::open(&root.0).unwrap();
    assert!(root.path("v2/credentials/00000.damaged-1").is_dir());
    assert_eq!(store.free_credential_key().unwrap(), Some(1700));
    let text = fs::read_to_string(readme).unwrap();
    assert!(text.starts_with("Local notes\n"));
    assert!(text.contains("00000.damaged-1"));
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

#[test]
fn non_discoverable_records_are_readable_bound_and_protect_the_parent() {
    let root = Directory::new();
    let store = Store::open(&root.0).unwrap();
    store.write(PARENT, &parent()).unwrap();
    let source = opensk::api::key_store::CredentialSource {
        wrapped_private_key: sk_cbor::cbor_array![
            -7,
            fixture_blob(Kind::Signing).encode().unwrap()
        ],
        rp_id_hash: [42; 32],
        cred_protect_policy: Some(
            opensk::ctap::data_formats::CredentialProtectionPolicy::UserVerificationRequired,
        ),
        cred_blob: Some(vec![7; 32]),
    };
    let id: [u8; 32] = store
        .create_non_discoverable(source)
        .unwrap()
        .try_into()
        .unwrap();
    let path = root.path("v2/non-discoverable").join("00000");
    let text = fs::read_to_string(path.join("metadata.ini")).unwrap();
    assert!(text.contains(&format!("rp_id_hash={}", hex_id(&[42; 32]))));
    assert!(text.contains("cred_protect_policy=3"));
    let loaded = store
        .read_non_discoverable(&id, &[42; 32])
        .unwrap()
        .unwrap();
    assert_eq!(loaded.cred_blob, Some(vec![7; 32]));
    assert!(
        store
            .read_non_discoverable(&id, &[43; 32])
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store.free_credential_key().unwrap(),
        Some(CREDENTIALS.start)
    );
    assert!(
        store
            .list()
            .unwrap()
            .iter()
            .all(|k| !CREDENTIALS.contains(k))
    );
    drop(store);
    let store = Store::open(&root.0).unwrap();
    assert!(
        store
            .read_non_discoverable(&id, &[42; 32])
            .unwrap()
            .is_some()
    );
    fs::write(path.join("tpm-signing-blob.bin"), b"corrupt").unwrap();
    assert!(
        store
            .read_non_discoverable(&id, &[42; 32])
            .unwrap()
            .is_none()
    );
    assert!(path.with_file_name("00000.damaged-1").is_dir());
    fs::remove_file(root.path("v2/authenticator/tpm-parent.bin")).unwrap();
    drop(store);
    assert!(Store::open(&root.0).is_err());
}
