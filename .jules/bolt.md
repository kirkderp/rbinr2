## 2024-03-24 - Unstable Sorts are Standard
**Learning:** Replacing `.sort()` with `.sort_unstable()` and `.sort_by()` with `.sort_unstable_by()` is a highly effective, low-risk optimization in Rust. It avoids allocations for preserving stability, saving CPU and memory. When sorting primitive values or vectors where stability isn't needed (like deduplication), it should be the standard approach.
**Action:** Always check if `.sort_unstable()` can be used instead of `.sort()` when implementing or reviewing sorting logic in Rust, especially when dealing with unique elements (e.g., hash keys).
