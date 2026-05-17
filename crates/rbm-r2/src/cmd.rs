use rbm_core::ToolResult;

use crate::session::Session;

/// Run a raw r2 command against an existing session.
///
/// # Errors
///
/// Returns an error if the r2 session worker is unavailable or if r2 rejects the
/// command.
pub async fn raw_cmd(session: &Session, command: &str) -> ToolResult<String> {
    session.cmd(command).await
}
