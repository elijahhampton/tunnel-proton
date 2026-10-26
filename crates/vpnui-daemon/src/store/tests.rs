use std::os::unix::fs::PermissionsExt;

use super::*;
use crate::profile::{Overrides, identity, parse};
use crate::testkeys::{TempDir, config, secret_forms};

fn uid() -> u32 {
    nix::unistd::geteuid().as_raw()
}

fn store(dir: &TempDir) -> ProfileStore {
    ProfileStore::new(dir.path().join("profiles"), uid())
}

fn import(store: &ProfileStore, n: u8, comment: &str, overrides: &Overrides) -> ImportOutcome {
    let parsed = parse(&config(n, comment, "203.0.113.40:51820")).unwrap();
    let id = identity(parsed.peer_comment.as_deref(), Some("file"), overrides).unwrap();
    store.import(parsed, id, UnixMillis(1_000)).unwrap()
}

#[test]
fn import_creates_private_dir_and_file() {
    let dir = TempDir::new("store").unwrap();
    let store = store(&dir);
    let outcome = import(&store, 1, "CO#4", &Overrides::default());
    assert!(!outcome.replaced);
    assert_eq!(outcome.profile.country_code.as_deref(), Some("CO"));

    let dir_mode = fs::metadata(store.dir()).unwrap().permissions().mode() & 0o777;
    assert_eq!(dir_mode, 0o700);
    let file = store.dir().join(format!("{}.json", outcome.profile.id));
    assert_eq!(
        fs::metadata(&file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    store.check_private().unwrap();

    let listed = store.list().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(
        listed[0].interface.private_key,
        outcome.profile.interface.private_key
    );
    assert_eq!(
        listed[0].peer.preshared_key,
        outcome.profile.peer.preshared_key
    );
    assert_eq!(listed[0].peer.endpoint, outcome.profile.peer.endpoint);
}

#[test]
fn reimporting_the_same_peer_updates_in_place() {
    let dir = TempDir::new("store").unwrap();
    let store = store(&dir);
    let first = import(&store, 1, "CO#4", &Overrides::default());
    let renamed = Overrides {
        name: Some("Bogotá".into()),
        country: Some("CO".into()),
        ..Overrides::default()
    };
    let second = import(&store, 1, "CO#4", &renamed);
    assert!(second.replaced);
    assert_eq!(
        second.profile.id, first.profile.id,
        "id is stable across re-imports"
    );
    let listed = store.list().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].name, "Bogotá");

    let other = import(&store, 2, "CO#4", &Overrides::default());
    assert_ne!(other.profile.id, first.profile.id);
    assert_eq!(store.list().unwrap().len(), 2);
}

#[test]
fn remove_deletes_the_file() {
    let dir = TempDir::new("store").unwrap();
    let store = store(&dir);
    let p = import(&store, 3, "US#1", &Overrides::default()).profile;
    assert_eq!(store.remove(&p.id).unwrap().id, p.id);
    assert!(store.list().unwrap().is_empty());
    assert!(matches!(store.remove(&p.id), Err(StoreError::NotFound(_))));
}

#[test]
fn atomic_write_replaces_or_leaves_the_old_file() {
    let dir = TempDir::new("atomic").unwrap();
    let path = dir.path().join("state.json");
    atomic_write(&path, b"first", 0o600).unwrap();
    atomic_write(&path, b"second", 0o600).unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"second");
    let leftovers: Vec<_> = fs::read_dir(dir.path())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
        .collect();
    assert!(leftovers.is_empty(), "temp files left behind");

    fs::set_permissions(dir.path(), Permissions::from_mode(0o500)).unwrap();
    let failed = atomic_write(&path, b"third", 0o600);
    fs::set_permissions(dir.path(), Permissions::from_mode(0o700)).unwrap();
    assert!(failed.is_err(), "read-only directory must fail");
    assert_eq!(
        fs::read(&path).unwrap(),
        b"second",
        "old contents survive a failed write"
    );
}

#[test]
fn public_dirs_are_refused() {
    let dir = TempDir::new("store").unwrap();
    let store = store(&dir);
    store.ensure_dir().unwrap();
    fs::set_permissions(store.dir(), Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        store.check_private(),
        Err(StoreError::NotPrivate { .. })
    ));
    let other_owner = ProfileStore::new(store.dir(), uid() + 1);
    fs::set_permissions(store.dir(), Permissions::from_mode(0o700)).unwrap();
    assert!(other_owner.check_private().is_err());
}

#[test]
fn corrupt_files_report_without_leaking_keys() {
    let dir = TempDir::new("store").unwrap();
    let store = store(&dir);
    let p = import(&store, 4, "SE#2", &Overrides::default()).profile;
    let path = store.dir().join(format!("{}.json", p.id));
    let text = fs::read_to_string(&path).unwrap();
    let broken = text.replacen("\"private_key\": \"", "\"private_key\": \"!!", 1);
    fs::write(&path, broken).unwrap();
    let error = store.list().unwrap_err().to_string();
    for form in secret_forms(4) {
        assert!(!error.contains(&form), "error leaked key material: {error}");
    }
}

#[test]
fn debug_output_of_profiles_is_redacted() {
    let dir = TempDir::new("store").unwrap();
    let store = store(&dir);
    let p = import(&store, 5, "JP#3", &Overrides::default()).profile;
    let shown = format!("{p:?} {:#?}", store.list().unwrap());
    for form in secret_forms(5) {
        assert!(!shown.contains(&form), "Debug leaked {form}");
    }
}
