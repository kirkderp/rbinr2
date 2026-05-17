use rbm_core::{ToolError, ToolResult};
use serde_json::{Value, json};

use crate::filters::{build_filter_regex, paginate};
use crate::search::{validate_hex_pattern, validate_search_pattern};
use crate::session::Session;

/// Return flags or flagspaces from r2.
///
/// # Errors
///
/// Returns an error if r2 returns invalid JSON or a filter regex is invalid.
pub async fn flags(
    session: &Session,
    mode: &str,
    offset: usize,
    limit: usize,
    filter: Option<&str>,
) -> ToolResult<Value> {
    let mode = normalize_flags_mode(mode)?;
    let raw = match mode {
        "flags" => session.cmdj("fj").await?,
        "realnames" => session.cmdj("fnj").await?,
        "flagspaces" => session.cmdj("fsj").await?,
        _ => unreachable!("mode is normalized before dispatch"),
    };
    let filtered = filter_flag_rows(raw, filter)?;
    let paged = if mode == "flagspaces" {
        filtered
    } else {
        paginate(filtered, offset, limit)
    };
    Ok(json!({
        "schema": "rbm.r2.flags.v0",
        "mode": mode,
        "offset": offset,
        "limit": limit,
        "result": paged,
    }))
}

fn filter_flag_rows(value: Value, filter: Option<&str>) -> ToolResult<Value> {
    let Some(pattern) = filter.filter(|s| !s.is_empty()) else {
        return Ok(value);
    };
    let regex = build_filter_regex(pattern)?;
    let Value::Array(rows) = value else {
        return Ok(value);
    };
    Ok(Value::Array(
        rows.into_iter()
            .filter(|row| {
                ["name", "realname", "flagname", "demname", "space"]
                    .iter()
                    .filter_map(|key| row.get(*key).and_then(Value::as_str))
                    .any(|s| regex.is_match(s))
            })
            .collect(),
    ))
}

/// Return a global xref inventory from r2 axlj.
///
/// # Errors
///
/// Returns an error if r2 returns invalid JSON.
pub async fn global_xrefs(session: &Session, offset: usize, limit: usize) -> ToolResult<Value> {
    let raw = session.cmdj("axlj").await?;
    let total = raw.as_array().map_or(0, Vec::len);
    let result = paginate(raw, offset, limit);
    Ok(json!({
        "schema": "rbm.r2.global_xrefs.v0",
        "offset": offset,
        "limit": limit,
        "total": total,
        "result": result,
    }))
}

/// Return pointer/reference-like words from a bounded memory range.
///
/// # Errors
///
/// Returns an error if the address is invalid, the byte count is outside the
/// bounded range, or r2 returns invalid JSON.
pub async fn pointer_scan(session: &Session, addr: &str, count: u64) -> ToolResult<Value> {
    crate::disasm::validate_addr(addr)?;
    if count == 0 || count > 1024 * 1024 {
        return Err(ToolError::invalid(
            "count must be between 1 and 1048576 bytes",
        ));
    }
    let raw = session.cmdj(format!("pxrj {count} @ {addr}")).await?;
    Ok(json!({
        "schema": "rbm.r2.pointer_scan.v0",
        "addr": addr,
        "count": count,
        "result": raw,
    }))
}

/// Decode a string at an address with one of r2's string printers.
///
/// # Errors
///
/// Returns an error if the mode or address is invalid, or if r2 returns invalid
/// JSON for the selected string printer.
pub async fn string_at(session: &Session, addr: &str, mode: &str) -> ToolResult<Value> {
    crate::disasm::validate_addr(addr)?;
    let mode = normalize_string_mode(mode)?;
    let command = match mode {
        "auto" => format!("psj @ {addr}"),
        "ascii" => format!("pszj @ {addr}"),
        "utf16" => format!("pswj @ {addr}"),
        "utf32" => format!("psWj @ {addr}"),
        "pascal" => format!("pspj @ {addr}"),
        _ => unreachable!("mode is normalized before dispatch"),
    };
    let raw = session.cmdj(command).await?;
    Ok(json!({
        "schema": "rbm.r2.string_at.v0",
        "addr": addr,
        "mode": mode,
        "result": raw,
    }))
}

/// Return r2 plugin/capability listings.
///
/// # Errors
///
/// Returns an error if the plugin mode or r2 command fails.
pub async fn plugins(session: &Session, mode: &str) -> ToolResult<Value> {
    let mode = normalize_plugin_mode(mode)?;
    let command = match mode {
        "asm" => "Laq",
        "analysis" => "LAq",
        "bin" => "Lbq",
        "hash" => "Lhq",
        "decompile" => "LDq",
        _ => unreachable!("mode is normalized before dispatch"),
    };
    let raw = session.cmd(command).await?;
    let plugins: Vec<String> = raw
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(String::from)
        .collect();
    Ok(json!({
        "schema": "rbm.r2.plugins.v0",
        "mode": mode,
        "count": plugins.len(),
        "plugins": plugins,
    }))
}

/// Run bounded read-only r2 semantic searches.
///
/// # Errors
///
/// Returns an error if the search mode, pattern, or r2 command fails.
pub async fn semantic_search(
    session: &Session,
    mode: &str,
    pattern: &str,
    limit: usize,
) -> ToolResult<Value> {
    let mode = normalize_semantic_search_mode(mode)?;
    let command = match mode {
        "opcode_type" => {
            validate_search_pattern(pattern)?;
            format!("/atj {pattern}")
        }
        "disasm" => {
            validate_search_pattern(pattern)?;
            format!("/adj {pattern}")
        }
        "wide_string" => {
            validate_search_pattern(pattern)?;
            format!("/wj {pattern}")
        }
        "value" => {
            validate_type_arg_for_search("pattern", pattern)?;
            format!("/vj {pattern}")
        }
        "refs" => {
            crate::disasm::validate_addr(pattern)?;
            format!("/rj {pattern}")
        }
        "rop" => {
            validate_search_pattern(pattern)?;
            format!("/Rj {pattern}")
        }
        "hex" => {
            validate_hex_pattern(pattern)?;
            format!("/xj {pattern}")
        }
        _ => unreachable!("mode is normalized before dispatch"),
    };
    let raw = session.cmdj(command).await?;
    let total = raw.as_array().map_or(0, Vec::len);
    let result = paginate(raw, 0, limit);
    Ok(json!({
        "schema": "rbm.r2.semantic_search.v0",
        "mode": mode,
        "pattern": pattern,
        "limit": limit,
        "total": total,
        "result": result,
    }))
}

pub fn normalize_flags_mode(mode: &str) -> ToolResult<&'static str> {
    match mode.trim() {
        "" | "flags" | "fj" => Ok("flags"),
        "realnames" | "demangled" | "fnj" => Ok("realnames"),
        "flagspaces" | "spaces" | "fsj" => Ok("flagspaces"),
        other => Err(ToolError::invalid(format!(
            "flags mode must be flags, realnames, or flagspaces; got {other:?}"
        ))),
    }
}

pub fn normalize_string_mode(mode: &str) -> ToolResult<&'static str> {
    match mode.trim() {
        "" | "auto" | "psj" => Ok("auto"),
        "ascii" | "zero" | "pszj" => Ok("ascii"),
        "utf16" | "wide" | "pswj" => Ok("utf16"),
        "utf32" | "psWj" => Ok("utf32"),
        "pascal" | "pspj" => Ok("pascal"),
        other => Err(ToolError::invalid(format!(
            "string mode must be auto, ascii, utf16, utf32, or pascal; got {other:?}"
        ))),
    }
}

pub fn normalize_plugin_mode(mode: &str) -> ToolResult<&'static str> {
    match mode.trim() {
        "" | "asm" | "arch" | "Laq" => Ok("asm"),
        "analysis" | "anal" | "LAq" => Ok("analysis"),
        "bin" | "binary" | "Lbq" => Ok("bin"),
        "hash" | "Lhq" => Ok("hash"),
        "decompile" | "decompiler" | "LDq" => Ok("decompile"),
        other => Err(ToolError::invalid(format!(
            "plugin mode must be asm, analysis, bin, hash, or decompile; got {other:?}"
        ))),
    }
}

pub fn normalize_semantic_search_mode(mode: &str) -> ToolResult<&'static str> {
    match mode.trim() {
        "" | "opcode_type" | "type" | "/atj" => Ok("opcode_type"),
        "disasm" | "asm_text" | "/adj" => Ok("disasm"),
        "wide_string" | "wide" | "/wj" => Ok("wide_string"),
        "value" | "/vj" => Ok("value"),
        "refs" | "references" | "/rj" => Ok("refs"),
        "rop" | "gadgets" | "/Rj" => Ok("rop"),
        "hex" | "bytes" | "/xj" => Ok("hex"),
        other => Err(ToolError::invalid(format!(
            "semantic search mode must be opcode_type, disasm, wide_string, value, refs, rop, or hex; got {other:?}"
        ))),
    }
}

fn validate_type_arg_for_search(label: &str, value: &str) -> ToolResult<()> {
    if value.trim().is_empty() {
        return Err(ToolError::invalid(format!("{label} is empty")));
    }
    if value
        .chars()
        .any(|c| matches!(c, ';' | '\n' | '\r' | '|') || c == char::from(0x60))
    {
        return Err(ToolError::invalid(format!(
            "{label} contains an r2 command separator: {value:?}"
        )));
    }
    Ok(())
}
