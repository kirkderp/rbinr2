## 2024-05-22 - Regex Recompilation Bottleneck
**Learning:** In highly frequent analysis passes (like disassembly loops parsing instructions), compiling regular expressions via `Regex::new()` on every iteration is a massive, silent bottleneck.
**Action:** Use `std::sync::OnceLock` (or `lazy_static`) to compile fixed `Regex` patterns exactly once at process start, reducing invocation overhead from milliseconds to microseconds.
