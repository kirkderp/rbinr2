## 2024-06-08 - Command Injection in r2 Eval Settings
**Vulnerability:** Command injection via the `arch` parameter in `e asm.arch={arch}` when configuring r2 session settings. User input was interpolated directly into the `cmd` function without sanitization.
**Learning:** Even internal configuration commands in Radare2 (like `e asm.arch=...`) are evaluated in a way that processes shell metacharacters (e.g. `;`, `!`). Any user-controlled string formatted into a `session.cmd()` or `session.cmdj()` call is a potential command injection vector.
**Prevention:** Always validate parameters with `crate::cmd::has_r2_shell_metacharacters` before interpolating them into r2 commands, regardless of whether the command is a query, an eval setting (`e`), or an analysis operation.
