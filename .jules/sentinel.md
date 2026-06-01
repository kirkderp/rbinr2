## 2024-06-01 - Command Injection Vulnerability in r2pipe inputs

**Vulnerability:** The `has_r2_shell_metacharacters` sanitizer in `crates/rbm-r2/src/cmd.rs` blocked many shell operators (`;`, `|`, `>`, etc.) but missed the variable expansion operator (`$`) and escape character (`\`). This allowed potential command injection via variable evaluation (e.g., executing commands nested within `$()`, or bypassing other checks with `\`).

**Learning:** Shell metacharacter sanitization needs to be exhaustive. Blacklisting a few obvious operators is insufficient because alternative command injection or evasion methods (like variable expansion or backslash escaping) can circumvent partial filters.

**Prevention:** Always include `$` and `\` in lists of prohibited characters when sanitizing user input meant for shells or shell-like parsers (like radare2's internal evaluation parser), or better yet, strictly validate and escape inputs rather than relying solely on blacklisting.