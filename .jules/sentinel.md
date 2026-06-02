## 2024-05-24 - Missing Shell Metacharacters in r2pipe input validation
**Vulnerability:** Radare2 inputs were not fully sanitized against shell metacharacters `$` and `\`, which could allow command injection and variable expansion in radare2 internal subshells or macros.
**Learning:** We need to exhaustively block all shell operators: `;`, `\n`, `\r`, `|`, `` ` ``, `>`, `<`, `&`, `!`, `$`, `\`.
**Prevention:** Using a unified `has_r2_shell_metacharacters` function in `cmd.rs` rather than duplicating the blocklist ensures consistent and complete sanitization across modules like `disasm` and `search`.
