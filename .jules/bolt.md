## 2024-06-25 - Replace Value cloning with slice references
**Learning:** Found unnecessary massive deep cloning of serde_json Value objects representing arrays by using `as_array().cloned().unwrap_or_default()`. This heavily allocates memory for objects in the tree.
**Action:** Replace `as_array().cloned().unwrap_or_default()` with `as_array().map(Vec::as_slice).unwrap_or_default()` to use a `&[Value]` instead of a `Vec<Value>` allocation, preventing the entire JSON tree from being deep-copied when only reading is needed.
