#![allow(unsafe_code)]

use std::path::PathBuf;

use rbm_core::CachePaths;

#[test]
fn cache_paths_subdirs() {
    let paths = CachePaths::new("/base");
    assert_eq!(paths.overflow_dir(), PathBuf::from("/base/overflow"));
    assert_eq!(paths.r2_dir(), PathBuf::from("/base/r2"));
    assert_eq!(
        paths.r2_session_dir("abc123"),
        PathBuf::from("/base/r2/abc123")
    );
    assert_eq!(paths.tmp_dir(), PathBuf::from("/base/tmp"));
}

#[test]
fn cache_paths_create_and_cleanup() {
    let dir = tempfile::tempdir().unwrap();
    let paths = CachePaths::new(dir.path().join("cache"));
    paths.ensure_all().unwrap();
    assert!(paths.overflow_dir().exists());
    assert!(paths.r2_dir().exists());
    assert!(paths.r2_session_dir("latest").parent().unwrap().exists());
    assert!(paths.tmp_dir().exists());
}

#[test]
fn cache_paths_root() {
    let paths = CachePaths::new("/custom/root");
    assert_eq!(paths.root(), PathBuf::from("/custom/root"));
}
