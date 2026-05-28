## 2024-05-24 - Exhaustive Shell Metacharacter Blocking for r2pipe
**Vulnerability:** Command injection risk via variable expansion (`$`) and line continuation/escaping (`\`) in radare2 internal shell capabilities.
**Learning:** Radare2 supports its own internal shell-like features including variable expansion and escaping. Simply blocking standard separators (`;`, `|`, `\n`) and output redirection (`>`, `<`) is insufficient to prevent arbitrary command execution or file writes when querying via r2pipe.
**Prevention:** Always maintain an exhaustive blocklist for `r2_cmd` inputs, treating it as equivalent to unsanitized shell execution unless metacharacters like `$`, `\`, `&`, `!`, `>`, `<`, `` ` ``, `|`, `;`, `\n`, `\r` are explicitly blocked or appropriately escaped.
