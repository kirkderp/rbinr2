## 2026-06-05 - Use unstable sort for standard types

**Learning:** When sorting primitive or standard library types (e.g., `Vec<PathBuf>`, `Vec<String>`) in Rust, `.sort_unstable()` and `.sort_unstable_by()` should be used over `.sort()` and `.sort_by()` unless stable sorting is explicitly needed. This convention avoids unnecessary memory allocations and improves performance.
**Action:** Replaced `.sort()` and `.sort_by()` with `.sort_unstable()` and `.sort_unstable_by()` respectively across the codebase to adhere to this codebase-specific performance convention.
