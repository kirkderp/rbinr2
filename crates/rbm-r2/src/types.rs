use rbm_core::{ToolError, ToolResult};
use serde_json::{Value, json};

use crate::filters::paginate;
use crate::search::glob_or_substring_match;
use crate::session::Session;

/// Validate a type name or format before interpolating it into an r2 command.
///
/// # Errors
///
/// Returns an error if the value is empty when required or contains an r2
/// command separator.
pub fn validate_type_arg(label: &str, value: &str, allow_empty: bool) -> ToolResult<()> {
    if !allow_empty && value.trim().is_empty() {
        return Err(ToolError::invalid(format!("{label} is empty")));
    }
    if crate::cmd::has_r2_shell_metacharacters(value) {
        return Err(ToolError::invalid(format!(
            "{label} contains an r2 command separator: {value:?}"
        )));
    }
    Ok(())
}

/// Return a bounded r2 type-system view.
///
/// # Errors
///
/// Returns an error if the mode, type name, or r2 command fails.
pub async fn types_view(
    session: &Session,
    mode: &str,
    type_name: Option<&str>,
    addr: Option<&str>,
    offset: usize,
    limit: usize,
    filter: Option<&str>,
) -> ToolResult<Value> {
    let mode = normalize_type_mode(mode)?;
    if let Some(type_name) = type_name {
        validate_type_arg("type_name", type_name, false)?;
    }
    if let Some(addr) = addr {
        crate::disasm::validate_addr(addr)?;
    }

    let result = match mode {
        "list" => {
            let raw = session.cmdj("tj").await?;
            let types = raw
                .get("types")
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or_default();
            let filtered = filter_named_rows(types, filter);
            paginate(Value::Array(filtered), offset, limit)
        }
        "functions" => {
            let raw = session.cmdj("tfj").await?;
            let types = raw.get("types").and_then(Value::as_array).map_or_else(
                || raw.as_array().map(Vec::as_slice).unwrap_or_default(),
                Vec::as_slice,
            );
            let filtered = filter_named_rows(types, filter);
            paginate(Value::Array(filtered), offset, limit)
        }
        "structs" => text_result(&session.cmd("ts").await?),
        "enums" => text_result(&session.cmd("te").await?),
        "unions" => text_result(&session.cmd("tu").await?),
        "typedefs" => text_result(&session.cmd("tt").await?),
        "c" => {
            let command = type_name.map_or_else(|| "tc".to_string(), |name| format!("tc {name}"));
            text_result(&session.cmd(command).await?)
        }
        "view" => {
            let name = type_name
                .ok_or_else(|| ToolError::invalid("type_name is required for mode=view"))?;
            text_result(&session.cmd(format!("tv {name}")).await?)
        }
        "format" => {
            let name = type_name
                .ok_or_else(|| ToolError::invalid("type_name is required for mode=format"))?;
            text_result(&session.cmd(format!("t {name}")).await?)
        }
        "cast" => {
            let name = type_name
                .ok_or_else(|| ToolError::invalid("type_name is required for mode=cast"))?;
            let addr = addr.ok_or_else(|| ToolError::invalid("addr is required for mode=cast"))?;
            text_result(&session.cmd(format!("tp {name} {addr}")).await?)
        }
        "type_xrefs" => {
            let command = type_name.map_or_else(|| "tx".to_string(), |name| format!("tx {name}"));
            text_result(&session.cmd(command).await?)
        }
        "function_type_xrefs" => {
            let command = addr.map_or_else(|| "txf".to_string(), |addr| format!("txf {addr}"));
            text_result(&session.cmd(command).await?)
        }
        "type_links" => session.cmdj("tlj").await?,
        "calling_conventions" => session.cmdj("tccj").await?,
        _ => unreachable!("mode is normalized before dispatch"),
    };

    Ok(json!({
        "schema": "rbm.r2.types.v0",
        "mode": mode,
        "type_name": type_name,
        "addr": addr,
        "offset": offset,
        "limit": limit,
        "result": result,
    }))
}

fn text_result(raw: &str) -> Value {
    json!({
        "format": "text",
        "text": raw,
    })
}

fn filter_named_rows(rows: &[Value], filter: Option<&str>) -> Vec<Value> {
    let Some(pattern) = filter.filter(|s| !s.is_empty()) else {
        return rows.to_vec();
    };
    let needle = pattern.to_lowercase();
    rows.iter()
        .filter(|row| {
            ["name", "type"]
                .iter()
                .filter_map(|key| row.get(*key).and_then(Value::as_str))
                .any(|s| glob_or_substring_match(&needle, &s.to_lowercase()))
        })
        .cloned()
        .collect()
}

/// Normalize accepted type modes.
///
/// # Errors
///
/// Returns an error if the mode is not supported.
pub fn normalize_type_mode(mode: &str) -> ToolResult<&'static str> {
    match mode.trim() {
        "" | "list" | "types" | "tj" => Ok("list"),
        "functions" | "funcs" | "tfj" => Ok("functions"),
        "structs" | "ts" => Ok("structs"),
        "enums" | "te" => Ok("enums"),
        "unions" | "tu" => Ok("unions"),
        "typedefs" | "tt" => Ok("typedefs"),
        "c" | "tc" => Ok("c"),
        "view" | "offsets" | "xrefs" | "tv" => Ok("view"),
        "format" | "pf" | "t" => Ok("format"),
        "cast" | "tp" => Ok("cast"),
        "type_xrefs" | "tx" => Ok("type_xrefs"),
        "function_type_xrefs" | "txf" => Ok("function_type_xrefs"),
        "type_links" | "links" | "tlj" => Ok("type_links"),
        "calling_conventions" | "cc" | "tccj" => Ok("calling_conventions"),
        other => Err(ToolError::invalid(format!(
            "type mode must be list, functions, structs, enums, unions, typedefs, c, view, format, cast, type_xrefs, function_type_xrefs, type_links, or calling_conventions; got {other:?}"
        ))),
    }
}
