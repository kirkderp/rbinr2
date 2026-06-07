## 2025-02-13 - Centralize Input Sanitization for r2pipe Commands

**Vulnerability:** Scattered and inconsistent validation of radare2 shell metacharacters in command inputs (e.g., in `check_no_r2_separators`).
**Learning:** Hardcoding lists of blocklisted characters (like `matches!(c, ';' | '\n' | '\r' | '|' | '`' | '>' | '<' | '&' | '!')`) across different modules risks omitting newer or less common metacharacters (e.g., `$`, `\`), leading to bypasses for command injection.
**Prevention:** Always use `crate::cmd::has_r2_shell_metacharacters` as the centralized single source of truth for input sanitization against command injection.
