## 2024-10-24 - Prefer sort_unstable for Primitive and Standard Types
**Learning:** This Rust codebase consistently favors `.sort_unstable()` and `.sort_unstable_by()` over `.sort()` and `.sort_by()` when sorting primitive or standard library types (e.g., `Vec<PathBuf>`, `Vec<String>`). This avoids unnecessary memory allocations inherent to stable sorts and improves sorting performance.
**Action:** Always default to `.sort_unstable()` or `.sort_unstable_by()` when sorting vectors, unless preserving the original order of equal elements is explicitly required by the business logic.
