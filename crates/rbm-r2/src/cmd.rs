use rbm_core::{ToolError, ToolResult};

use crate::session::Session;

/// Run a raw r2 command against an existing session.
///
/// # Errors
///
/// Returns an error if the r2 session worker is unavailable or if r2 rejects the
/// command.
pub async fn raw_cmd(session: &Session, command: &str) -> ToolResult<String> {
    validate_query_command(command)?;
    session.cmd(command).await
}

/// Validate that a raw command is a single read-oriented r2 query.
///
/// `r2_cmd` is an escape hatch for inspection, not a mutation API. Keeping it
/// read-oriented avoids silent persistent-session poisoning across later tools.
///
/// # Errors
///
/// Returns an error for empty commands, r2 command separators, shell escapes,
/// and common state/file mutation command forms.
pub fn validate_query_command(command: &str) -> ToolResult<()> {
    let trimmed = command.trim();
    if trimmed.is_empty() {
        return Err(ToolError::invalid("r2_cmd command is empty"));
    }
    if has_r2_shell_metacharacters(trimmed) {
        return Err(ToolError::invalid(format!(
            "r2_cmd accepts one query command; separators, redirects, and shell escapes are not allowed: {command:?}"
        )));
    }

    let first = trimmed.split_whitespace().next().unwrap_or(trimmed);
    if first.starts_with('w') {
        return Err(ToolError::invalid(format!(
            "r2_cmd is read-only; write command {first:?} is not allowed"
        )));
    }
    if matches!(first, "oo" | "ood" | "oodf" | "doo" | "doc" | "dos") || first == "o" {
        return Err(ToolError::invalid(format!(
            "r2_cmd is read-only; open/debug mutation command {first:?} is not allowed"
        )));
    }
    if first == "s" || first.starts_with("s+") || first.starts_with("s-") {
        return Err(ToolError::invalid(
            "r2_cmd is read-only; seek mutation commands are not allowed",
        ));
    }
    if first == "e" && trimmed.contains('=') {
        return Err(ToolError::invalid(
            "r2_cmd is read-only; use named tools instead of mutating r2 eval settings",
        ));
    }
    Ok(())
}

/// Validate a string input to ensure it contains no dangerous radare2 shell metacharacters
/// or query modifiers.
///
/// Under the hood, radare2 supports shell redirection, pipes, and subshell executions
/// using character tokens like `;`, `|`, `&`, `!`, `>`, `<`, `` ` ``, `\n`, `\r`, `$`, `\`.
/// This helper detects any such characters.
#[must_use]
pub fn has_r2_shell_metacharacters(value: &str) -> bool {
    value.chars().any(|c| {
        matches!(
            c,
            ';' | '\n' | '\r' | '|' | '`' | '>' | '<' | '&' | '!' | '$' | '\\'
        )
    })
}

#[cfg(test)]
mod tests {
    use super::{has_r2_shell_metacharacters, validate_query_command};

    #[test]
    fn allows_read_queries() {
        assert!(validate_query_command("ij").is_ok());
        assert!(validate_query_command("aflj").is_ok());
        assert!(validate_query_command("e asm.arch").is_ok());
    }

    #[test]
    fn rejects_obvious_mutations_and_separators() {
        assert!(validate_query_command("e asm.arch=x86").is_err());
        assert!(validate_query_command("wx 90").is_err());
        assert!(validate_query_command("ij; wx 90").is_err());
        assert!(validate_query_command("!sh").is_err());
        assert!(validate_query_command("ij > /tmp/out").is_err());
    }

    #[test]
    fn rejects_all_shell_operators() {
        assert!(has_r2_shell_metacharacters("cmd; injection"));
        assert!(has_r2_shell_metacharacters("cmd\ninjection"));
        assert!(has_r2_shell_metacharacters("cmd\rinjection"));
        assert!(has_r2_shell_metacharacters("cmd|injection"));
        assert!(has_r2_shell_metacharacters("cmd`injection`"));
        assert!(has_r2_shell_metacharacters("cmd > file"));
        assert!(has_r2_shell_metacharacters("cmd < file"));
        assert!(has_r2_shell_metacharacters("cmd & background"));
        assert!(has_r2_shell_metacharacters("!shell"));
        assert!(has_r2_shell_metacharacters("cmd $var"));
        assert!(has_r2_shell_metacharacters("cmd \\escape"));
        assert!(!has_r2_shell_metacharacters("aflj"));
    }
}
