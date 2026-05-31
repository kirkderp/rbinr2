## 2024-05-31 - Command Injection via Shell Expansion in Radare2
**Vulnerability:** The `r2_cmd` interface failed to block `$` and `\` metacharacters, potentially allowing command injection via variable expansion and subshell escapes during radare2 command execution.
**Learning:** Radare2's internal shell supports more than standard redirection/pipes; it expands variables and supports escape sequences. All r2pipe inputs must be exhaustively sanitized against the full set of shell-like capabilities supported by radare2.
**Prevention:** Exhaustively block shell metacharacters like `<`, `>`, `&`, `!`, `$`, and `\` in user-supplied radare2 commands. Use exact allowlists for commands when possible instead of broad denylists for metacharacters.
