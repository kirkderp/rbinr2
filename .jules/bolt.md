## 2024-05-28 - Sort unstable for Vec primitives
**Learning:** In Rust, sorting standard primitive types (e.g., `Vec<PathBuf>`, `Vec<String>`) that don't depend on stable order can be significantly optimized by switching from `sort()` to `sort_unstable()`, which requires no allocations and avoids the overhead of stable sort. This applies directly to data paths inside the memory representation.
**Action:** Always favor `.sort_unstable()` and `.sort_unstable_by()` over `.sort()` and `.sort_by()` when sorting primitive or standard library types if stable sorting isn't needed.
