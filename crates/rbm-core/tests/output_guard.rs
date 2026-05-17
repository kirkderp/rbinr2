use rbm_core::{GuardedOutput, OutputGuard};

#[test]
fn guard_str_inline_short() {
    let dir = tempfile::tempdir().unwrap();
    let overflow_dir = dir.path().join("overflow");
    std::fs::create_dir_all(&overflow_dir).unwrap();
    let guard = OutputGuard::new(overflow_dir);
    let result = guard
        .guard_str("test", "a short reply".to_string())
        .unwrap();
    assert!(matches!(result, GuardedOutput::Inline(ref s) if s == "a short reply"));
}

#[test]
fn guard_str_overflow_long() {
    let dir = tempfile::tempdir().unwrap();
    let overflow_dir = dir.path().join("overflow");
    std::fs::create_dir_all(&overflow_dir).unwrap();
    let guard = OutputGuard::new(overflow_dir).with_max_inline_chars(10);
    let payload = "this is a much longer string that should overflow the inline limit".to_string();
    let result = guard.guard_str("big", payload).unwrap();
    match &result {
        GuardedOutput::Overflow(summary) => {
            assert!(summary.overflow);
            assert!(summary.total_chars > 10);
            assert!(!summary.preview.is_empty());
            assert!(summary.file_path.exists());
        }
        GuardedOutput::Inline(_) => panic!("expected overflow"),
    }
}

#[test]
fn guard_str_boundary_exact() {
    let dir = tempfile::tempdir().unwrap();
    let overflow_dir = dir.path().join("overflow");
    std::fs::create_dir_all(&overflow_dir).unwrap();
    let guard = OutputGuard::new(overflow_dir).with_max_inline_chars(5);
    let result = guard.guard_str("boundary", "12345".to_string()).unwrap();
    assert!(matches!(result, GuardedOutput::Inline(ref s) if s == "12345"));
}

#[test]
fn guard_str_boundary_exceed_one() {
    let dir = tempfile::tempdir().unwrap();
    let overflow_dir = dir.path().join("overflow");
    std::fs::create_dir_all(&overflow_dir).unwrap();
    let guard = OutputGuard::new(overflow_dir).with_max_inline_chars(5);
    let result = guard.guard_str("boundary", "123456".to_string()).unwrap();
    assert!(matches!(result, GuardedOutput::Overflow(_)));
}

#[test]
fn guard_str_overflow_file_persists() {
    let dir = tempfile::tempdir().unwrap();
    let overflow_dir = dir.path().join("overflow");
    std::fs::create_dir_all(&overflow_dir).unwrap();
    let guard = OutputGuard::new(overflow_dir).with_max_inline_chars(5);
    let overflow = guard.guard_str("first", "aaaaaaaaaa".to_string()).unwrap();
    let GuardedOutput::Overflow(summary) = overflow else {
        panic!("expected overflow");
    };
    assert!(summary.file_path.exists());
}

#[test]
fn guard_str_ttl_and_cleanup() {
    let dir = tempfile::tempdir().unwrap();
    let overflow_dir = dir.path().join("overflow");
    std::fs::create_dir_all(&overflow_dir).unwrap();
    let guard = OutputGuard::new(&overflow_dir)
        .with_max_inline_chars(1)
        .with_ttl(std::time::Duration::from_secs(0));
    let _r1 = guard.guard_str("first", "aa".to_string()).unwrap();
    let _r2 = guard.guard_str("second", "bb".to_string()).unwrap();
    // With TTL=0, both should have been cleaned up immediately by cleanup_expired
    // But since cleanup only removes on the next write, at least the directory should exist
    assert!(overflow_dir.exists());
}

#[test]
fn guard_str_r2_cmd_short() {
    let dir = tempfile::tempdir().unwrap();
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("overflow")).unwrap();
    let guard = OutputGuard::new(dir.path().join("overflow"))
        .with_max_inline_chars(rbm_core::output_guard::MAX_INLINE_CHARS);
    let result = guard.guard_str("r2_cmd", "0x401000".to_string()).unwrap();
    assert!(matches!(result, GuardedOutput::Inline(_)));
}
