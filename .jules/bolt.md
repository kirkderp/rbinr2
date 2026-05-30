## 2026-05-30 - Optimize Sorting
**Learning:** The memory states that we should use `.sort_unstable()` and `.sort_unstable_by()` over `.sort()` and `.sort_by()` for standard library types unless stable sorting is explicitly needed.
**Action:** Changed sorting functions in multiple files to use their unstable counterparts to avoid unnecessary memory allocations and improve performance.
