use rbm_core::ToolResult;
use serde_json::Value;

use crate::session::Session;

/// Return r2's general file metadata JSON.
///
/// # Errors
///
/// Returns an error if the r2 command fails or the response is not valid JSON.
pub async fn info(session: &Session) -> ToolResult<Value> {
    session.cmdj("ij").await
}

/// Return the r2 rich-header view.
///
/// # Errors
///
/// Returns an error if the r2 command fails.
pub async fn rich_header(session: &Session) -> ToolResult<String> {
    session.cmd("iH").await
}

/// Return r2's version-information view.
///
/// # Errors
///
/// Returns an error if the r2 command fails.
pub async fn version_info(session: &Session) -> ToolResult<String> {
    session.cmd("iV").await
}

/// Return r2's entry-point inventory.
///
/// # Errors
///
/// Returns an error if the r2 command fails or the response is not valid JSON.
pub async fn entry_points(session: &Session) -> ToolResult<Value> {
    session.cmdj("iej").await
}
