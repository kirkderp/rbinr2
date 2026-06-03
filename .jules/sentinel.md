## 2024-06-03 - [CRITICAL] Prevent Command Injection via Variable Expansion/Escape Characters
**Vulnerability:** The `has_r2_shell_metacharacters` check in `crates/rbm-r2/src/cmd.rs` blocked many shell metacharacters but missed `$` (variable expansion/command substitution) and `\` (escape characters).
**Learning:** Radare2's internal shell-like capabilities can be abused through unescaped variable expansion or escape sequences, which could potentially lead to arbitrary file writes or command injection if inputs are not strictly sanitized.
**Prevention:** Always ensure exhaustive input sanitization for r2pipe commands by blocking `$` and `\` along with other metacharacters (`<`, `>`, `&`, `!`, etc.). Use `crate::cmd::has_r2_shell_metacharacters` as the single source of truth.
