## 2024-03-24 - [Command Injection via Radare2 Shell Operators]
**Vulnerability:** Radare2 inputs were missing `$`, `\` from their shell metacharacter blocklist, allowing potential command injection/environment variable leaks via `$()` subshells and `$` variables.
**Learning:** Even if `!`, `>`, `<` are blocked, variable expansion (`$`) and escapes (`\`) can still lead to command evaluation inside custom shell environments. It's critical to consider environment-specific injection techniques (like Radare2's variable expansion).
**Prevention:** Ensure exhaustive blocklisting of shell metacharacters for environments that support variable expansion and escaping, explicitly including `$`, `\` and `~`.
