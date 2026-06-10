## 2024-05-18 - Unnecessary cloning of `serde_json::Value` objects
**Learning:** Found unnecessary deep cloning of `serde_json::Value` items via `.as_array().cloned()` before passing arrays through filters that might reject a large chunk of items.
**Action:** Changed array parsing to output slices `&[Value]` with `.map(Vec::as_slice)` instead of cloning the whole array. Update functions that filter or process arrays to accept slices, and apply `.cloned()` only when adding matched objects into new allocations.
