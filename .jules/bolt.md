## 2026-05-31 - Use unstable sorting for primitive types
**Learning:** The standard `.sort()` and `.sort_by()` methods in Rust use a stable sorting algorithm, which can be slower and allocate memory. When sorting primitive types (like `PathBuf` or `String`) or when stable sorting is not required, `.sort_unstable()` and `.sort_unstable_by()` should be used instead for better performance.
**Action:** Use `.sort_unstable()` and `.sort_unstable_by()` across the codebase for standard types unless stability is explicitly required.
