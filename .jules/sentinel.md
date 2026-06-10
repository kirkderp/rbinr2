## 2024-05-24 - [Command Injection via Restored Radare2 Settings]
**Vulnerability:** The internal implementation to backup and restore radare2 environment evaluation settings (e.g. `e asm.bits`) parsed the current state into strings, and applied them verbatim when restoring the session. A malicious r2 configuration could pollute the current state, causing command injection during the session restoration phase by supplying shell operators in place of strings.
**Learning:** Even internal configuration elements read from third-party tools should be exhaustively validated before interpolating into command streams.
**Prevention:** Apply `has_r2_shell_metacharacters` logic consistently on all setting variables that originate from `e ...` reads before injecting them into write templates.
