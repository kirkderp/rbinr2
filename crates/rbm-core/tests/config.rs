#![allow(unsafe_code, clippy::undocumented_unsafe_blocks)]

use std::path::PathBuf;


use rbm_core::CachePaths;

static ENV_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct EnvGuard(String);

impl EnvGuard {
    fn set(key: &str, value: &str) -> Self {
        let prev = std::env::var(key).ok().unwrap_or_default();
        unsafe {
            std::env::set_var(key, value);
        }
        Self(prev)
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        if self.0.is_empty() {
            unsafe {
                std::env::remove_var("RBM_CACHE_DIR");
            }
        } else {
            unsafe {
                std::env::set_var("RBM_CACHE_DIR", &self.0);
            }
        }
    }
}

#[test]
fn cache_paths_env_overrides() {
    let _lock = ENV_GUARD.lock().unwrap();

    let _guard = EnvGuard::set("RBM_CACHE_DIR", "/tmp/rbinr2-cache-test");
    let paths = CachePaths::from_env().unwrap();
    assert_eq!(
        paths.root(),
        PathBuf::from("/tmp/rbinr2-cache-test").as_path()
    );
}

#[test]
fn cache_paths_default() {
    let _lock = ENV_GUARD.lock().unwrap();

    unsafe {
        std::env::remove_var("RBM_CACHE_DIR");
    }
    let paths = CachePaths::from_env().unwrap();
    assert_eq!(paths.root(), PathBuf::from("./rbinr2-cache").as_path());
}

#[test]
fn cache_paths_empty_env() {
    let _lock = ENV_GUARD.lock().unwrap();

    let _guard = EnvGuard::set("RBM_CACHE_DIR", "");
    assert!(CachePaths::from_env().is_err());
}

#[test]
fn cache_paths_construct_subs() {
    let _lock = ENV_GUARD.lock().unwrap();

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
fn cache_paths_ensure_all_creates_dirs() {
    let _lock = ENV_GUARD.lock().unwrap();

    let dir = tempfile::tempdir().unwrap();
    let paths = CachePaths::new(dir.path().join("cache"));
    paths.ensure_all().unwrap();
    assert!(paths.overflow_dir().exists());
    assert!(paths.r2_dir().exists());
    assert!(paths.tmp_dir().exists());
}
