use rbm_core::{ToolError, ToolResult};
use serde_json::{Value, json};

use crate::search::glob_or_substring_match;
use crate::session::Session;

/// Return r2 section metadata.
///
/// # Errors
///
/// Returns an error if the r2 command fails or the response is not valid JSON.
pub async fn sections(session: &Session) -> ToolResult<Value> {
    session.cmdj("iSj").await
}

/// Return r2 relocation metadata.
///
/// # Errors
///
/// Returns an error if the r2 command fails or the response is not valid JSON.
pub async fn relocations(session: &Session) -> ToolResult<Value> {
    session.cmdj("irj").await
}

/// Return r2 resource metadata.
///
/// # Errors
///
/// Returns an error if the r2 command fails or the response is not valid JSON.
pub async fn resources(session: &Session) -> ToolResult<Value> {
    session.cmdj("iRj").await
}

/// Return imported library names from r2 metadata.
///
/// # Errors
///
/// Returns an error if an r2 inventory command fails or the response cannot be decoded.
pub async fn libraries(session: &Session) -> ToolResult<Vec<String>> {
    let json = session.cmdj("ilj").await?;
    if let Some(names) = extract_library_names(&json) {
        return Ok(names);
    }
    let text = session.cmd("ilq").await?;
    Ok(parse_libraries_text(&text))
}

pub fn extract_library_names(value: &Value) -> Option<Vec<String>> {
    let arr = value.as_array()?;
    Some(arr.iter().map(extract_library_name).collect())
}

pub fn extract_library_name(item: &Value) -> String {
    if let Some(s) = item.as_str() {
        return s.to_string();
    }
    if let Some(obj) = item.as_object() {
        if let Some(s) = obj.get("string").and_then(Value::as_str) {
            return s.to_string();
        }
        if let Some(s) = obj.get("name").and_then(Value::as_str) {
            return s.to_string();
        }
    }
    item.to_string()
}

pub fn parse_libraries_text(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(String::from)
        .collect()
}

/// Return r2 class metadata.
///
/// # Errors
///
/// Returns an error if the r2 command fails or the response is not valid JSON.
pub async fn classes(session: &Session) -> ToolResult<Value> {
    session.cmdj("icj").await
}

/// Return a bounded projection of r2 native vtable discovery.
///
/// # Errors
///
/// Returns an error if the r2 command fails or the response is not valid JSON.
pub async fn vtables(session: &Session, offset: usize, limit: usize) -> ToolResult<Value> {
    let raw = session.cmdj("avj").await?;
    Ok(project_vtables(&raw, offset, limit))
}

#[must_use]
pub fn project_vtables(raw: &Value, offset: usize, limit: usize) -> Value {
    let rows = raw.as_array().cloned().unwrap_or_default();
    let total = rows.len();
    let limit = if limit == 0 { 50 } else { limit.min(500) };
    let vtables: Vec<Value> = rows.into_iter().skip(offset).take(limit).collect();
    json!({
        "schema": "rbm.r2.vtables.v0",
        "offset": offset,
        "limit": limit,
        "count": vtables.len(),
        "total": total,
        "vtables": vtables,
    })
}

/// Return r2's text view for a class.
///
/// # Errors
///
/// Returns an error if the class name is unsafe for r2 command interpolation or
/// if the r2 command fails.
pub async fn class_methods(session: &Session, classname: &str) -> ToolResult<String> {
    validate_classname(classname)?;
    session.cmd(format!("ic {classname}")).await
}

/// Return a compact JSON projection for a class.
///
/// # Errors
///
/// Returns an error if the class name is unsafe for r2 command interpolation, if
/// the r2 class inventory command fails, or if the response is not valid JSON.
pub async fn class_methods_json(session: &Session, classname: &str) -> ToolResult<Value> {
    validate_classname(classname)?;
    let raw = classes(session).await?;
    Ok(project_class_methods(&raw, classname))
}

/// Validate a class name before interpolating it into an r2 command.
///
/// # Errors
///
/// Returns an error if the class name contains an r2 command separator.
pub fn validate_classname(classname: &str) -> ToolResult<()> {
    if crate::cmd::has_r2_shell_metacharacters(classname) {
        return Err(ToolError::invalid(format!(
            "classname contains an r2 command separator: {classname:?}"
        )));
    }
    Ok(())
}

/// Filter class metadata by class name.
///
/// # Errors
///
/// Returns an error if `pattern` is not a valid regular expression.
pub fn filter_classes(value: Value, pattern: &str) -> ToolResult<Value> {
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
                .get("classname")
                .and_then(Value::as_str)
                .or_else(|| item.get("name").and_then(Value::as_str))
                .unwrap_or("")
                .to_lowercase();
            glob_or_substring_match(&needle, &name)
        })
        .collect();
    Ok(Value::Array(filtered))
}

pub fn project_class_methods(value: &Value, classname: &str) -> Value {
    let Some(arr) = value.as_array() else {
        return json!({
            "classname": classname,
            "method_count": 0,
            "methods": [],
            "field_count": 0,
            "fields": [],
            "found": false,
        });
    };

    let target = arr.iter().find(|item| {
        item.get("classname")
            .and_then(Value::as_str)
            .or_else(|| item.get("name").and_then(Value::as_str))
            == Some(classname)
    });

    let Some(target) = target else {
        return json!({
            "classname": classname,
            "method_count": 0,
            "methods": [],
            "field_count": 0,
            "fields": [],
            "found": false,
        });
    };

    let mut methods: Vec<Value> = target
        .get("methods")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|item| {
            json!({
                "name": item.get("name").and_then(Value::as_str).unwrap_or(""),
                "realname": item.get("realname").and_then(Value::as_str),
                "addr": item.get("addr").and_then(Value::as_u64).map(|v| format!("{v:#x}")),
                "vaddr": item.get("vaddr").and_then(Value::as_u64).map(|v| format!("{v:#x}")),
                "flags": item.get("flags").cloned().unwrap_or_else(|| json!([])),
            })
        })
        .collect();
    methods.sort_unstable_by(|a, b| {
        (
            a.get("name").and_then(Value::as_str).unwrap_or(""),
            a.get("realname").and_then(Value::as_str).unwrap_or(""),
            a.get("addr").and_then(Value::as_str).unwrap_or(""),
        )
            .cmp(&(
                b.get("name").and_then(Value::as_str).unwrap_or(""),
                b.get("realname").and_then(Value::as_str).unwrap_or(""),
                b.get("addr").and_then(Value::as_str).unwrap_or(""),
            ))
    });

    let mut fields: Vec<Value> = target
        .get("fields")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|item| {
            json!({
                "name": item.get("name").and_then(Value::as_str).unwrap_or(""),
                "type": item.get("type").and_then(Value::as_str),
                "addr": item.get("addr").and_then(Value::as_u64).map(|v| format!("{v:#x}")),
                "vaddr": item.get("vaddr").and_then(Value::as_u64).map(|v| format!("{v:#x}")),
                "flags": item.get("flags").cloned().unwrap_or_else(|| json!([])),
            })
        })
        .collect();
    fields.sort_unstable_by(|a, b| {
        (
            a.get("name").and_then(Value::as_str).unwrap_or(""),
            a.get("type").and_then(Value::as_str).unwrap_or(""),
            a.get("addr").and_then(Value::as_str).unwrap_or(""),
        )
            .cmp(&(
                b.get("name").and_then(Value::as_str).unwrap_or(""),
                b.get("type").and_then(Value::as_str).unwrap_or(""),
                b.get("addr").and_then(Value::as_str).unwrap_or(""),
            ))
    });

    json!({
        "classname": classname,
        "found": true,
        "method_count": methods.len(),
        "methods": methods,
        "field_count": fields.len(),
        "fields": fields,
    })
}
