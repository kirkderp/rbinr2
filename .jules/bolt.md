## 2024-05-18 - [Rust Sorting Optimization]
**Learning:** In Rust, `sort_unstable()` and `sort_unstable_by()` do not allocate memory and are faster than `sort()` and `sort_by()` which allocate memory and maintain stability. Unless stability is explicitly needed, always prefer unstable sorting for primitive and standard library types.
**Action:** Replaced `.sort()` with `.sort_unstable()` and `.sort_by()` with `.sort_unstable_by()` throughout the `rbm-r2` crate to reduce memory allocations and improve performance.
