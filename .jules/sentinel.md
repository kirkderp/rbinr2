## 2024-05-24 - Arbitrary File Write via r2cmd Redirection
**Vulnerability:** The internal `r2cmd` capability (used to interact with radare2 sessions) lacked input sanitization against the `>` character. This allowed malicious payloads to redirect output to arbitrary files on the system using shell-like output redirection in the radare2 command.
**Learning:** Even internal tool commands must thoroughly validate input when they wrap tools like `radare2` that implement shell-like operators internally. It is crucial to comprehensively block separators and output redirectors like `>`, `<`, `|`, `;` and backticks.
**Prevention:** Ensured the input validator explicitly denies the `>` character before the command is sent to the r2 session.
