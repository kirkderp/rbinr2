## 2024-05-24 - Rust Vector Sorting Performance
**Learning:** In Rust, `.sort()` uses a stable sorting algorithm (Timsort) which requires additional memory allocations. For primitive types or when stability is not required, `.sort_unstable()` (Pattern-defeating quicksort) is faster and doesn't allocate.
**Action:** Default to `.sort_unstable()` and `.sort_unstable_by()` for `Vec<T>` where `T` is a primitive type, `String`, or `PathBuf`, unless stable sorting is explicitly needed.
