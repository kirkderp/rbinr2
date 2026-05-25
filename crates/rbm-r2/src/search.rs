use rbm_core::{ToolError, ToolResult};
use serde_json::{Value, json};

use crate::session::Session;
use crate::{disasm, symbols};

/// Validate a text search pattern before interpolating it into an r2 command.
///
/// # Errors
///
/// Returns an error if the pattern is empty or contains an r2 command separator.
pub fn validate_search_pattern(pattern: &str) -> ToolResult<()> {
    if pattern.is_empty() {
        return Err(ToolError::invalid("search pattern is empty"));
    }
    if pattern
        .chars()
        .any(|c| matches!(c, ';' | '\n' | '\r' | '|' | '`' | '>' | '<' | '&' | '!'))
    {
        return Err(ToolError::invalid(format!(
            "search pattern contains an r2 command separator: {pattern:?}"
        )));
    }
    Ok(())
}

/// Validate an r2 byte-search pattern.
///
/// # Errors
///
/// Returns an error if the pattern is empty or contains characters other than
/// hex digits, `.` wildcards, or whitespace.
pub fn validate_hex_pattern(hex: &str) -> ToolResult<()> {
    if hex.is_empty() {
        return Err(ToolError::invalid("hex pattern is empty"));
    }
    if !hex
        .chars()
        .all(|c| c.is_ascii_hexdigit() || c == '.' || c.is_ascii_whitespace())
    {
        return Err(ToolError::invalid(format!(
            "hex pattern must only contain hex digits, '.' wildcards, and whitespace: {hex:?}"
        )));
    }
    Ok(())
}

/// Search strings through r2's `/j` command.
///
/// # Errors
///
/// Returns an error if the pattern is invalid, the r2 command fails, or the
/// response is not valid JSON.
pub async fn search_strings(session: &Session, pattern: &str) -> ToolResult<Value> {
    validate_search_pattern(pattern)?;
    session.cmdj(format!("/j {pattern}")).await
}

/// Search bytes through r2's `/xj` command.
///
/// # Errors
///
/// Returns an error if the hex pattern is invalid, the r2 command fails, or the
/// response is not valid JSON.
pub async fn search_bytes(session: &Session, hex_pattern: &str) -> ToolResult<Value> {
    validate_hex_pattern(hex_pattern)?;
    session.cmdj(format!("/xj {hex_pattern}")).await
}

/// Search one of the supported r2 inventories.
///
/// # Errors
///
/// Returns an error if the selected search requires an r2 command that fails or
/// returns invalid JSON, or if a byte-search pattern is invalid.
pub async fn find(
    session: &Session,
    search_type: &str,
    pattern: &str,
    limit: usize,
) -> ToolResult<Value> {
    let cap = if limit == 0 { usize::MAX } else { limit };
    let results = match search_type {
        "functions" => find_functions(session, pattern, cap).await?,
        "strings" => find_strings(session, pattern, cap).await?,
        "imports" => find_imports(session, pattern, cap).await?,
        "bytes" => find_bytes(session, pattern, cap).await?,
        other => {
            return Err(ToolError::invalid(format!(
                "unknown search_type {other:?}; expected functions, strings, imports, or bytes"
            )));
        }
    };
    Ok(json!({
        "schema": "rbm.r2.find.v0",
        "search_type": search_type,
        "pattern": pattern,
        "limit": limit,
        "count": results.len(),
        "results": results,
    }))
}

async fn find_functions(session: &Session, pattern: &str, cap: usize) -> ToolResult<Vec<Value>> {
    let funcs = disasm::functions(session).await?;
    Ok(filter_functions(funcs, pattern, cap))
}

pub fn filter_functions(funcs: Value, pattern: &str, cap: usize) -> Vec<Value> {
    let arr = into_array(funcs);
    let needle = pattern.to_lowercase();
    let mut out: Vec<Value> = Vec::new();
    for fn_ in arr {
        let name = fn_.get("name").and_then(Value::as_str).unwrap_or("");
        if !glob_or_substring_match(&needle, &name.to_lowercase()) {
            continue;
        }
        let addr = fn_
            .get("addr")
            .or_else(|| fn_.get("offset"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let size = fn_.get("size").and_then(Value::as_u64).unwrap_or(0);
        out.push(json!({
            "addr": format!("{addr:#x}"),
            "name": name,
            "size": size,
        }));
        if out.len() >= cap {
            break;
        }
    }
    out
}

async fn find_strings(session: &Session, pattern: &str, cap: usize) -> ToolResult<Vec<Value>> {
    let strs = symbols::strings_all(session, 4).await?;
    Ok(filter_strings(strs, pattern, cap))
}

pub fn filter_strings(strs: Value, pattern: &str, cap: usize) -> Vec<Value> {
    let arr = into_array(strs);
    let needle = pattern.to_lowercase();
    let mut out: Vec<Value> = Vec::new();
    for s in arr {
        let text = s.get("string").and_then(Value::as_str).unwrap_or("");
        if !text.to_lowercase().contains(&needle) {
            continue;
        }
        let addr = s
            .get("vaddr")
            .or_else(|| s.get("paddr"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let section = s
            .get("section")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        out.push(json!({
            "addr": format!("{addr:#x}"),
            "string": text,
            "section": section,
        }));
        if out.len() >= cap {
            break;
        }
    }
    out
}

async fn find_imports(session: &Session, pattern: &str, cap: usize) -> ToolResult<Vec<Value>> {
    let imps = symbols::imports(session).await?;
    Ok(filter_imports(imps, pattern, cap))
}

pub fn filter_imports(imps: Value, pattern: &str, cap: usize) -> Vec<Value> {
    let arr = into_array(imps);
    let needle = pattern.to_lowercase();
    let mut out: Vec<Value> = Vec::new();
    for imp in arr {
        let name = imp
            .get("name")
            .and_then(Value::as_str)
            .or_else(|| imp.get("realname").and_then(Value::as_str))
            .unwrap_or("");
        let lib = imp
            .get("libname")
            .or_else(|| imp.get("lib"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let matches = [name, lib]
            .iter()
            .any(|value| value.to_lowercase().contains(&needle));
        if !matches {
            continue;
        }
        let addr = imp
            .get("plt")
            .or_else(|| imp.get("vaddr"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        out.push(json!({
            "addr": format!("{addr:#x}"),
            "name": name,
            "lib": lib,
        }));
        if out.len() >= cap {
            break;
        }
    }
    out
}

async fn find_bytes(session: &Session, hex_pattern: &str, cap: usize) -> ToolResult<Vec<Value>> {
    let raw = search_bytes(session, hex_pattern).await?;
    Ok(into_array(raw).into_iter().take(cap).collect())
}

fn into_array(value: Value) -> Vec<Value> {
    match value {
        Value::Array(a) => a,
        _ => Vec::new(),
    }
}

#[must_use]
pub fn glob_or_substring_match(pattern_lower: &str, name_lower: &str) -> bool {
    if name_lower.contains(pattern_lower) {
        return true;
    }
    glob_match(pattern_lower, name_lower)
}

#[must_use]
pub fn glob_match(pattern: &str, text: &str) -> bool {
    if pattern.is_ascii() && text.is_ascii() {
        return glob_match_bytes(pattern.as_bytes(), text.as_bytes());
    }

    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let mut pi = 0usize;
    let mut ti = 0usize;
    let mut star: Option<usize> = None;
    let mut star_t = 0usize;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            star_t = ti;
            pi += 1;
        } else if let Some(sp) = star {
            pi = sp + 1;
            star_t += 1;
            ti = star_t;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

fn glob_match_bytes(p: &[u8], t: &[u8]) -> bool {
    let mut pi = 0usize;
    let mut ti = 0usize;
    let mut star: Option<usize> = None;
    let mut star_t = 0usize;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star = Some(pi);
            star_t = ti;
            pi += 1;
        } else if let Some(sp) = star {
            pi = sp + 1;
            star_t += 1;
            ti = star_t;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::filter_imports;

    #[test]
    fn filter_imports_matches_library_names() {
        let imports = json!([
            {
                "name": "CloseHandle",
                "libname": "KERNEL32.dll",
                "plt": 4096
            },
            {
                "name": "MessageBoxA",
                "libname": "USER32.dll",
                "plt": 8192
            }
        ]);

        let results = filter_imports(imports, "kernel", 10);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["name"], "CloseHandle");
        assert_eq!(results[0]["lib"], "KERNEL32.dll");
    }

    #[test]
    fn filter_strings_accepts_file_offset_strings() {
        let strings = json!([
            {
                "string": "This program cannot be run",
                "paddr": 29,
                "section": ""
            }
        ]);

        let results = super::filter_strings(strings, "program", 10);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["addr"], "0x1d");
    }
}
