use rbm_core::ToolError;

#[test]
fn tool_error_invalid() {
    let err = ToolError::invalid("bad input");
    assert_eq!(format!("{err}"), "invalid input: bad input");
}

#[test]
fn tool_error_io() {
    let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
    let err = ToolError::io("/tmp/foo", io_err);
    assert!(err.to_string().contains("file not found"));
    assert!(err.to_string().contains("/tmp/foo"));
}

#[test]
fn tool_error_backend() {
    let err = ToolError::backend("r2", "connection failed");
    assert!(err.to_string().contains("r2"));
    assert!(err.to_string().contains("connection failed"));
}

#[test]
fn tool_error_not_found() {
    let err = ToolError::not_found("symbol not found");
    assert_eq!(err.to_string(), "not found: symbol not found");
}

#[test]
fn tool_error_not_implemented() {
    let err = ToolError::NotImplemented { tool: "test_tool" };
    assert_eq!(err.to_string(), "tool not implemented yet: test_tool");
}
