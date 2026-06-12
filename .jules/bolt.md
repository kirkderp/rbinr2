## 2026-06-12 - Prevent massive JSON value cloning with `.as_array().map(Vec::as_slice)`

**Learning:** When retrieving JSON arrays from `serde_json::Value` items via `.and_then(Value::as_array)` or `.as_array()`, using `.cloned().unwrap_or_default()` forces a deep clone of the entire array and all its nested values. Since these arrays are often just iterated over to project some metadata, the deep clone causes severe and unnecessary memory allocation pressure.

**Action:** Whenever iterating or passing slices of `serde_json::Value` array elements without modifying them, replace `.and_then(Value::as_array).cloned().unwrap_or_default()` with `.and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default()`. This returns a reference to the underlying slice (`&[Value]`) and avoids deep cloning completely, reducing memory usage significantly.
