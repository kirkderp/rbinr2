use rbm_core::ToolResult;
use serde_json::{Map, Value, json};

use crate::search::glob_or_substring_match;
use crate::session::Session;

/// Return r2 import metadata.
///
/// # Errors
///
/// Returns an error if the r2 command fails or the response is not valid JSON.
pub async fn imports(session: &Session) -> ToolResult<Value> {
    session.cmdj("iij").await
}

/// Return imports grouped by library or namespace.
///
/// # Errors
///
/// Returns an error if the r2 command fails or the response is not valid JSON.
pub async fn imports_grouped(session: &Session) -> ToolResult<Value> {
    let raw = session.cmdj("iicj").await?;
    Ok(project_grouped_imports(&raw))
}

/// Return r2 export metadata.
///
/// # Errors
///
/// Returns an error if the r2 command fails or the response is not valid JSON.
pub async fn exports(session: &Session) -> ToolResult<Value> {
    session.cmdj("iEj").await
}

/// Return r2 symbol metadata.
///
/// # Errors
///
/// Returns an error if the r2 command fails or the response is not valid JSON.
pub async fn symbols(session: &Session) -> ToolResult<Value> {
    session.cmdj("isj").await
}

/// Return data-section strings filtered by minimum length.
///
/// # Errors
///
/// Returns an error if the r2 command fails or the response is not valid JSON.
pub async fn strings(session: &Session, min_length: usize) -> ToolResult<Value> {
    let raw = session.cmdj("izj").await?;
    Ok(filter_by_min_length(raw, min_length))
}

/// Return all strings filtered by minimum length.
///
/// # Errors
///
/// Returns an error if the r2 command fails or the response is not valid JSON.
pub async fn strings_all(session: &Session, min_length: usize) -> ToolResult<Value> {
    let raw = session.cmdj("izzj").await?;
    Ok(filter_by_min_length(raw, min_length))
}

/// Filter symbol-like metadata by name using glob/substring matching.
///
/// Consistent with `r2_find`'s function filter — supports `*`, `?` globs and
/// substring matching. This is intentional: agents should get predictable
/// filter behavior across tools without regex parse errors.
///
/// # Errors
///
/// Returns an error if `pattern` is empty.
pub fn filter_by_name(value: Value, pattern: &str) -> ToolResult<Value> {
    if pattern.is_empty() {
        return Ok(value);
    }
    let needle = pattern.to_lowercase();
    let Value::Array(arr) = value else {
        return Ok(value);
    };
    let filtered: Vec<Value> = arr
        .into_iter()
        .filter(|item| {
            let name = item
                .get("name")
                .and_then(Value::as_str)
                .or_else(|| item.get("realname").and_then(Value::as_str))
                .unwrap_or("")
                .to_lowercase();
            glob_or_substring_match(&needle, &name)
        })
        .collect();
    Ok(Value::Array(filtered))
}

/// Filter string metadata by string content using glob/substring matching.
///
/// # Errors
///
/// Returns an error if `pattern` is empty.
pub fn filter_by_string_content(value: Value, pattern: &str) -> ToolResult<Value> {
    if pattern.is_empty() {
        return Ok(value);
    }
    let needle = pattern.to_lowercase();
    let Value::Array(arr) = value else {
        return Ok(value);
    };
    let filtered: Vec<Value> = arr
        .into_iter()
        .filter(|item| {
            let s = item
                .get("string")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_lowercase();
            glob_or_substring_match(&needle, &s)
        })
        .collect();
    Ok(Value::Array(filtered))
}

#[must_use]
pub fn filter_by_min_length(value: Value, min_length: usize) -> Value {
    let Value::Array(arr) = value else {
        return value;
    };
    let filtered: Vec<Value> = arr
        .into_iter()
        .filter(|item| {
            let len = item.get("length").and_then(Value::as_u64).unwrap_or(0);
            usize::try_from(len).unwrap_or(usize::MAX) >= min_length
        })
        .collect();
    Value::Array(filtered)
}

#[must_use]
pub fn project_grouped_imports(value: &Value) -> Value {
    let Some(obj) = value.as_object() else {
        return json!({
            "group_count": 0,
            "groups": [],
        });
    };

    let mut group_names: Vec<_> = obj.keys().cloned().collect();
    group_names.sort();

    let groups: Vec<Value> = group_names
        .into_iter()
        .map(|group_name| {
            let imports_obj = obj
                .get(&group_name)
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_else(Map::new);
            let mut import_names: Vec<_> = imports_obj.keys().cloned().collect();
            import_names.sort();
            let imports: Vec<Value> = import_names
                .into_iter()
                .map(|import_name| {
                    let mut callers: Vec<String> = imports_obj
                        .get(&import_name)
                        .and_then(Value::as_array)
                        .map(|arr| {
                            arr.iter()
                                .filter_map(Value::as_str)
                                .map(ToString::to_string)
                                .collect()
                        })
                        .unwrap_or_default();
                    callers.sort();
                    callers.dedup();
                    json!({
                        "name": import_name,
                        "caller_count": callers.len(),
                        "callers": callers,
                    })
                })
                .collect();
            json!({
                "name": group_name,
                "import_count": imports.len(),
                "imports": imports,
            })
        })
        .collect();

    json!({
        "group_count": groups.len(),
        "groups": groups,
    })
}
