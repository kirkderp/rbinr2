use rbm_core::{ToolError, ToolResult};
use regex::Regex;
use serde_json::Value;

/// Compile a case-insensitive regex used by r2 projection filters.
///
/// # Errors
///
/// Returns an error if `pattern` is not a valid regular expression.
pub fn build_filter_regex(pattern: &str) -> ToolResult<Regex> {
    regex::RegexBuilder::new(pattern)
        .case_insensitive(true)
        .build()
        .map_err(|e| ToolError::invalid(format!("invalid regex filter: {e}")))
}

#[must_use]
pub fn paginate(value: Value, offset: usize, limit: usize) -> Value {
    let Value::Array(arr) = value else {
        return value;
    };
    let take_count = if limit == 0 { usize::MAX } else { limit };
    Value::Array(arr.into_iter().skip(offset).take(take_count).collect())
}
