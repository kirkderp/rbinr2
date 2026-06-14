## 2024-06-14 - Prevent Command Injection via Quotes
**Vulnerability:** Radare2's `r2pipe` commands are vulnerable to command injection and escaping if single or double quotes are passed in the command strings without sanitization.
**Learning:** Radare2 supports internal shell-like capabilities. Input sanitization for `r2pipe` commands must exhaustively block shell metacharacters like `<`, `>`, `&`, `!`, `$`, `\`, `"`, and `'`. `has_r2_shell_metacharacters` was missing `'` and `"`.
**Prevention:** Always sanitize all user inputs containing shell metacharacters using the centralized `has_r2_shell_metacharacters` function before executing radare2 commands.
