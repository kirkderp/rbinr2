## 2024-05-24 - Missing Quote Sanitization in Command Filter
**Vulnerability:** Command injection vulnerability due to missing quote characters (`"` and `'`) in the `has_r2_shell_metacharacters` sanitization filter.
**Learning:** Radare2 inputs must be exhaustively sanitized. Leaving out quotes allows attackers to escape string arguments and potentially inject arbitrary r2 commands or execute internal macros/shell commands, bypassing initial filters.
**Prevention:** Always include `"` and `'` when blocking shell metacharacters for command interpreters or complex internal CLI tools like radare2, and maintain a comprehensive whitelist of safe characters where possible.
