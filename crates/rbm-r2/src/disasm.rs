use rbm_core::{ToolError, ToolResult};
use serde_json::{Value, json};

use crate::session::Session;

#[derive(Debug, Clone, Copy)]
pub enum XrefDir {
    To,
    From,
}

impl XrefDir {
    /// Parse an MCP-facing xref direction.
    ///
    /// # Errors
    ///
    /// Returns an error if `direction` is not `to`, `from`, or empty.
    pub fn parse(direction: &str) -> ToolResult<Self> {
        match direction {
            "to" | "" => Ok(Self::To),
            "from" => Ok(Self::From),
            other => Err(ToolError::invalid(format!(
                "xref direction must be 'to' or 'from', got {other:?}"
            ))),
        }
    }
}

/// Validate an address expression before interpolating it into an r2 command.
///
/// # Errors
///
/// Returns an error if the address is empty or contains an r2 command separator.
pub fn validate_addr(addr: &str) -> ToolResult<()> {
    check_no_r2_separators("addr", addr)
}

/// Validate a labeled value against r2 command separators.
///
/// Use this when the MCP parameter name differs from "addr" (e.g., "pattern" in
/// `r2_semantic_search mode=refs`), so the error message mentions the correct parameter.
///
/// # Errors
///
/// Returns an error if the value is empty or contains an r2 command separator.
pub fn validate_value(label: &str, value: &str) -> ToolResult<()> {
    check_no_r2_separators(label, value)
}

#[must_use]
pub fn missing_function_response(addr: &str) -> Value {
    json!({
        "addr": addr,
        "error": format!("No function at {addr}"),
        "suggested_next_tools": [
            {
                "tool": "r2_disassemble",
                "reason": "show a bounded instruction window from this exact address without requiring function recognition"
            },
            {
                "tool": "r2_lookup_address",
                "reason": "map the address to nearby flags, symbols, strings, sections, and any enclosing function"
            },
            {
                "tool": "r2_find_xrefs",
                "reason": "search strings, imports, functions, or bytes and immediately resolve references to each hit"
            }
        ],
    })
}

/// Validate a calculator expression before interpolating it into an r2 command.
///
/// # Errors
///
/// Returns an error if the expression is empty or contains an r2 command separator.
pub fn validate_expression(expression: &str) -> ToolResult<()> {
    check_no_r2_separators("expression", expression)
}

fn check_no_r2_separators(label: &str, value: &str) -> ToolResult<()> {
    if value.is_empty() {
        return Err(ToolError::invalid(format!(
            "{label} is empty; pass an address, symbol, or r2 flag in the MCP parameter named \"{label}\".",
        )));
    }
    if value
        .chars()
        .any(|c| matches!(c, ';' | '\n' | '\r' | '|' | '`' | '>' | '<' | '&' | '!'))
    {
        return Err(ToolError::invalid(format!(
            "{label} contains an r2 command separator: {value:?}"
        )));
    }
    Ok(())
}

/// Return the analyzed function list from r2.
///
/// # Errors
///
/// Returns an error if the r2 command fails or the response is not valid JSON.
pub async fn functions(session: &Session) -> ToolResult<Value> {
    session.cmdj("aflj").await
}

/// Read bytes from an address as an r2 hex string.
///
/// # Errors
///
/// Returns an error if the address is invalid or the r2 command fails.
pub async fn get_bytes(session: &Session, addr: &str, count: u64) -> ToolResult<String> {
    validate_addr(addr)?;
    session.cmd(format!("p8 {count} @ {addr}")).await
}

/// Resolve an address to r2's nearby symbol and function metadata.
///
/// # Errors
///
/// Returns an error if the address is invalid, an r2 command fails, or function
/// metadata is not valid JSON.
pub async fn lookup_address(session: &Session, addr: &str) -> ToolResult<Value> {
    validate_addr(addr)?;
    let description = session.cmd(format!("fd @ {addr}")).await?;
    let description = description.trim().to_string();
    let func_info = session.cmdj(format!("afij @ {addr}")).await?;
    Ok(build_lookup_result(addr, &description, func_info))
}

/// Return r2's address classification metadata for an address.
///
/// # Errors
///
/// Returns an error if the address is invalid, the r2 command fails, or the
/// response is not valid JSON.
pub async fn address_info(session: &Session, addr: &str) -> ToolResult<Value> {
    validate_addr(addr)?;
    let raw = session.cmdj(format!("aij @ {addr}")).await?;
    Ok(json!({
        "schema": "rbm.r2.address_info.v0",
        "addr": addr,
        "result": raw,
    }))
}

#[must_use]
pub fn build_lookup_result(addr: &str, description: &str, func_info: Value) -> Value {
    let func = first_function(func_info);
    let (function, function_offset) = func.map_or((None, None), |f| {
        let name = f
            .get("name")
            .and_then(Value::as_str)
            .map(std::string::ToString::to_string);
        let offset = f
            .get("offset")
            .or_else(|| f.get("addr"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        (name, Some(format!("{offset:#x}")))
    });
    json!({
        "addr": addr,
        "description": description,
        "function": function,
        "function_offset": function_offset,
    })
}

#[must_use]
pub fn first_function(value: Value) -> Option<Value> {
    match value {
        Value::Array(mut arr) if !arr.is_empty() => Some(arr.remove(0)),
        Value::Object(_) => Some(value),
        _ => None,
    }
}

/// Evaluate an r2 numeric expression and return radix-expanded output when possible.
///
/// # Errors
///
/// Returns an error if the expression is invalid or the r2 command fails.
pub async fn calculate(session: &Session, expression: &str) -> ToolResult<Value> {
    validate_expression(expression)?;
    let raw = session.cmd(format!("?v {expression}")).await?;
    let result = raw.trim().to_string();
    Ok(build_calculate_result(expression, &result))
}

/// Return r2 opcode-analysis rows for a bounded instruction window.
///
/// # Errors
///
/// Returns an error if the address is invalid, the r2 command fails, or the
/// response is not valid JSON.
pub async fn opcodes(session: &Session, addr: &str, count: u32) -> ToolResult<Value> {
    validate_addr(addr)?;
    let count = count.clamp(1, 500);
    let raw = session.cmdj(format!("aoj {count} @ {addr}")).await?;
    Ok(json!({
        "schema": "rbm.r2.opcodes.v0",
        "addr": addr,
        "count": count,
        "opcodes": raw,
    }))
}

/// Return a bounded radare2 block hash or entropy result.
///
/// # Errors
///
/// Returns an error if the address, byte count, algorithm, or r2 command fails.
pub async fn block_hash(
    session: &Session,
    addr: &str,
    count: u64,
    algorithm: &str,
) -> ToolResult<Value> {
    validate_addr(addr)?;
    if count == 0 || count > 16 * 1024 * 1024 {
        return Err(ToolError::invalid(format!(
            "count must be between 1 and {} bytes",
            16 * 1024 * 1024
        )));
    }
    let algorithm = normalize_hash_algorithm(algorithm)?;
    let raw = session
        .cmd(format!("ph {algorithm} {count} @ {addr}"))
        .await?;
    let value = raw.trim().to_string();
    Ok(json!({
        "schema": "rbm.r2.block_hash.v0",
        "addr": addr,
        "count": count,
        "algorithm": algorithm,
        "value": value,
    }))
}

/// Normalize accepted r2 hash algorithm names.
///
/// # Errors
///
/// Returns an error if the algorithm is not supported by this bounded wrapper.
pub fn normalize_hash_algorithm(algorithm: &str) -> ToolResult<&'static str> {
    match algorithm.trim() {
        "" | "sha256" => Ok("sha256"),
        "sha1" => Ok("sha1"),
        "sha512" => Ok("sha512"),
        "md5" => Ok("md5"),
        "crc32" => Ok("crc32"),
        "entropy" => Ok("entropy"),
        other => Err(ToolError::invalid(format!(
            "hash algorithm must be sha256, sha1, sha512, md5, crc32, or entropy; got {other:?}"
        ))),
    }
}

#[must_use]
pub fn build_calculate_result(expression: &str, result: &str) -> Value {
    parse_radix_u64(result).map_or_else(
        || {
            json!({
                "expression": expression,
                "result": result,
            })
        },
        |val| {
            json!({
                "expression": expression,
                "hex": result,
                "decimal": val.to_string(),
                "binary": format!("0b{val:b}"),
            })
        },
    )
}

#[must_use]
pub fn parse_radix_u64(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return u64::from_str_radix(rest, 16).ok();
    }
    if let Some(rest) = s.strip_prefix("0b").or_else(|| s.strip_prefix("0B")) {
        return u64::from_str_radix(rest, 2).ok();
    }
    if let Some(rest) = s.strip_prefix("0o").or_else(|| s.strip_prefix("0O")) {
        return u64::from_str_radix(rest, 8).ok();
    }
    s.parse::<u64>().ok()
}

/// Return r2's call graph text for a function.
///
/// # Errors
///
/// Returns an error if the address is invalid or the r2 command fails.
pub async fn callgraph(session: &Session, addr: &str) -> ToolResult<String> {
    validate_addr(addr)?;
    session.cmd(format!("agc @ {addr}")).await
}

/// Export one of r2's native analysis graphs.
///
/// # Errors
///
/// Returns an error if the graph kind, format, or address is invalid, if r2
/// rejects the graph command, or if JSON output cannot be decoded.
pub async fn graph(
    session: &Session,
    kind: &str,
    format: &str,
    addr: Option<&str>,
) -> ToolResult<Value> {
    let kind = normalize_graph_kind(kind)?;
    let format = normalize_graph_format(format)?;
    if let Some(addr) = addr {
        validate_addr(addr)?;
    }
    let command = graph_command(kind, format, addr);
    if format == "json" {
        let raw = session.cmdj(command).await?;
        Ok(json!({
            "schema": "rbm.r2.graph.v0",
            "kind": kind,
            "format": format,
            "addr": addr,
            "graph": raw,
        }))
    } else {
        let raw = session.cmd(command).await?;
        Ok(json!({
            "schema": "rbm.r2.graph.v0",
            "kind": kind,
            "format": format,
            "addr": addr,
            "graph": raw,
        }))
    }
}

fn graph_command(kind: &str, format: &str, addr: Option<&str>) -> String {
    let prefix = match kind {
        "function" => "agf",
        "callgraph" => "agc",
        "global_callgraph" => "agC",
        "imports" => "agi",
        "refs" => "agr",
        "global_refs" => "agR",
        "xrefs" => "agx",
        "data_refs" => "aga",
        "global_data_refs" => "agA",
        _ => unreachable!("graph kind is normalized before command construction"),
    };
    let suffix = match format {
        "text" => "",
        "json" => "j",
        "dot" => "d",
        "mermaid" => "m",
        _ => unreachable!("graph format is normalized before command construction"),
    };
    addr.map_or_else(
        || format!("{prefix}{suffix}"),
        |addr| format!("{prefix}{suffix} @ {addr}"),
    )
}

/// Normalize r2 graph kinds exposed through ag.
///
/// # Errors
///
/// Returns an error if the kind is not one of the supported r2 graph commands.
pub fn normalize_graph_kind(kind: &str) -> ToolResult<&'static str> {
    match kind.trim() {
        "" | "function" | "cfg" | "agf" => Ok("function"),
        "callgraph" | "calls" | "agc" => Ok("callgraph"),
        "global_callgraph" | "global_calls" | "agC" => Ok("global_callgraph"),
        "imports" | "agi" => Ok("imports"),
        "refs" | "references" | "agr" => Ok("refs"),
        "global_refs" | "global_references" | "agR" => Ok("global_refs"),
        "xrefs" | "crossrefs" | "agx" => Ok("xrefs"),
        "data_refs" | "data" | "aga" => Ok("data_refs"),
        "global_data_refs" | "global_data" | "agA" => Ok("global_data_refs"),
        other => Err(ToolError::invalid(format!(
            "graph kind must be function, callgraph, global_callgraph, imports, refs, global_refs, xrefs, data_refs, or global_data_refs; got {other:?}"
        ))),
    }
}

/// Normalize r2 graph output formats exposed through ag.
///
/// # Errors
///
/// Returns an error if the format is not one of the supported non-interactive
/// r2 graph formats.
pub fn normalize_graph_format(format: &str) -> ToolResult<&'static str> {
    match format.trim() {
        "" | "json" | "agj" => Ok("json"),
        "text" | "ascii" => Ok("text"),
        "dot" | "graphviz" => Ok("dot"),
        "mermaid" | "mmd" => Ok("mermaid"),
        other => Err(ToolError::invalid(format!(
            "graph format must be json, text, dot, or mermaid; got {other:?}"
        ))),
    }
}

/// Disassemble a fixed number of instructions at an address.
///
/// # Errors
///
/// Returns an error if the address is invalid or the r2 command fails.
pub async fn disassemble(session: &Session, addr: &str, count: u64) -> ToolResult<String> {
    validate_addr(addr)?;
    session.cmd(format!("pd {count} @ {addr}")).await
}

/// Disassemble the containing function at an address.
///
/// # Errors
///
/// Returns an error if the address is invalid or the r2 command fails.
pub async fn disassemble_function(session: &Session, addr: &str) -> ToolResult<String> {
    validate_addr(addr)?;
    session.cmd(format!("pdf @ {addr}")).await
}

/// Return a shaped JSON disassembly range.
///
/// # Errors
///
/// Returns an error if the address is invalid, the r2 command fails, or the
/// response is not valid JSON.
#[allow(clippy::too_many_lines)]
pub async fn disassemble_json(session: &Session, addr: &str, count: u64) -> ToolResult<Value> {
    validate_addr(addr)?;
    let raw = session.cmdj(format!("pdj {count} @ {addr}")).await?;
    Ok(shape_disassembly_range(addr, &raw))
}

/// Return a shaped JSON function disassembly.
///
/// # Errors
///
/// Returns an error if the address is invalid, the r2 command fails, or the
/// response is not valid JSON.
pub async fn disassemble_function_json(session: &Session, addr: &str) -> ToolResult<Value> {
    validate_addr(addr)?;
    let raw = session.cmdj(format!("pdfj @ {addr}")).await?;
    Ok(shape_disassembly_function(addr, &raw))
}

/// Return basic-block metadata for the containing function.
///
/// # Errors
///
/// Returns an error if the address is invalid, the r2 command fails, or the
/// response is not valid JSON.
pub async fn basic_blocks(session: &Session, addr: &str) -> ToolResult<Value> {
    validate_addr(addr)?;
    let raw = session.cmdj(format!("afbj @ {addr}")).await?;
    Ok(shape_basic_blocks(addr, raw))
}

/// Return a compact function CFG projection.
///
/// # Errors
///
/// Returns an error if the address is invalid, the r2 command fails, or the
/// response is not valid JSON.
pub async fn function_cfg(session: &Session, addr: &str) -> ToolResult<Value> {
    validate_addr(addr)?;
    let raw = session.cmdj(format!("agfj @ {addr}")).await?;
    Ok(shape_function_cfg(addr, &raw))
}

/// Return normalized function reference metadata.
///
/// # Errors
///
/// Returns an error if the address is invalid, the r2 command fails, or the
/// response is not valid JSON.
pub async fn function_refs(session: &Session, addr: &str) -> ToolResult<Value> {
    validate_addr(addr)?;
    let raw = session.cmdj(format!("afxj @ {addr}")).await?;
    Ok(shape_function_refs(addr, &raw))
}

/// Return ESIL-derived register and memory access summaries.
///
/// # Errors
///
/// Returns an error if the address or mode is invalid, the r2 command fails, or
/// the response is not valid JSON.
pub async fn esil_accesses(
    session: &Session,
    addr: &str,
    mode: &str,
    count: u32,
) -> ToolResult<Value> {
    validate_addr(addr)?;
    let mode = normalize_esil_access_mode(mode)?;
    let count = count.clamp(1, 5000);
    let command = match mode {
        "instructions" => format!("aeaj {count} @ {addr}"),
        "bytes" => format!("aeAj {count} @ {addr}"),
        "block" => format!("aeabj @ {addr}"),
        "function" => format!("aeafj @ {addr}"),
        _ => unreachable!("mode is normalized before dispatch"),
    };
    let raw = session.cmdj(command).await?;
    Ok(shape_esil_accesses(addr, mode, count, &raw))
}

/// Normalize accepted aliases for the ESIL access mode.
///
/// # Errors
///
/// Returns an error if the mode is not one of the supported ESIL access modes.
pub fn normalize_esil_access_mode(mode: &str) -> ToolResult<&'static str> {
    match mode.trim() {
        "" | "instructions" | "instrs" | "ops" | "aeaj" => Ok("instructions"),
        "bytes" | "len" | "aeaj_bytes" | "aeAj" => Ok("bytes"),
        "block" | "bb" | "basic_block" | "aeabj" => Ok("block"),
        "function" | "func" | "fcn" | "aeafj" => Ok("function"),
        other => Err(ToolError::invalid(format!(
            "unknown r2 ESIL access mode {other:?}; expected instructions, bytes, block, or function"
        ))),
    }
}

/// Return normalized variable xref read/write sites for a function.
///
/// # Errors
///
/// Returns an error if the address is invalid, the r2 command fails, or the
/// response is not valid JSON.
pub async fn variable_xrefs(session: &Session, addr: &str) -> ToolResult<Value> {
    validate_addr(addr)?;
    let raw = session.cmdj(format!("afvxj @ {addr}")).await?;
    Ok(shape_variable_xrefs(addr, &raw))
}

#[must_use]
pub fn shape_esil_accesses(addr: &str, mode: &str, count: u32, raw: &Value) -> Value {
    let access = raw.as_object();
    let registers_all = clone_array_field(access, "A");
    let registers_input = clone_array_field(access, "I");
    let registers_read = clone_array_field(access, "R");
    let registers_written = clone_array_field(access, "W");
    let registers_not_written = clone_array_field(access, "N");
    let values = clone_array_field(access, "V");
    let memory_reads = hex_array_field(access, "@R");
    let memory_writes = hex_array_field(access, "@W");
    json!({
        "addr": addr,
        "mode": mode,
        "count": count,
        "register_counts": {
            "all": registers_all.len(),
            "input": registers_input.len(),
            "read": registers_read.len(),
            "written": registers_written.len(),
            "not_written": registers_not_written.len(),
        },
        "memory_read_count": memory_reads.len(),
        "memory_write_count": memory_writes.len(),
        "value_count": values.len(),
        "registers_all": registers_all,
        "registers_input": registers_input,
        "registers_read": registers_read,
        "registers_written": registers_written,
        "registers_not_written": registers_not_written,
        "values_preview": values.into_iter().take(50).collect::<Vec<_>>(),
        "memory_reads": memory_reads,
        "memory_writes": memory_writes,
    })
}

#[must_use]
pub fn shape_variable_xrefs(addr: &str, raw: &Value) -> Value {
    let reads = shape_var_xref_entries(raw.get("reads"));
    let writes = shape_var_xref_entries(raw.get("writes"));
    let read_site_count = count_var_sites(&reads);
    let write_site_count = count_var_sites(&writes);
    json!({
        "addr": addr,
        "read_var_count": reads.len(),
        "write_var_count": writes.len(),
        "read_site_count": read_site_count,
        "write_site_count": write_site_count,
        "reads": reads,
        "writes": writes,
    })
}

fn clone_array_field(access: Option<&serde_json::Map<String, Value>>, key: &str) -> Vec<Value> {
    access
        .and_then(|m| m.get(key))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn hex_array_field(access: Option<&serde_json::Map<String, Value>>, key: &str) -> Vec<Value> {
    clone_array_field(access, key)
        .into_iter()
        .filter_map(|value| value_to_hex(&value))
        .map(Value::String)
        .collect()
}

fn shape_var_xref_entries(value: Option<&Value>) -> Vec<Value> {
    let Some(entries) = value.and_then(Value::as_array) else {
        return Vec::new();
    };
    entries
        .iter()
        .map(|entry| {
            let name = entry.get("name").and_then(Value::as_str).unwrap_or("");
            let addrs: Vec<Value> = entry
                .get("addrs")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(value_to_hex)
                .map(Value::String)
                .collect();
            json!({
                "name": name,
                "site_count": addrs.len(),
                "addrs": addrs,
            })
        })
        .collect()
}

fn count_var_sites(entries: &[Value]) -> usize {
    entries
        .iter()
        .map(|entry| {
            entry
                .get("addrs")
                .and_then(Value::as_array)
                .map_or(0, Vec::len)
        })
        .sum()
}

fn value_to_hex(value: &Value) -> Option<String> {
    if let Some(n) = value.as_u64() {
        return Some(format!("{n:#x}"));
    }
    if let Some(n) = value.as_i64() {
        return Some(format!("{n:#x}"));
    }
    value.as_str().map(ToOwned::to_owned)
}

pub fn cyclomatic_complexity(blocks: &Value) -> i64 {
    let Some(arr) = blocks.as_array() else {
        return 0;
    };
    if arr.is_empty() {
        return 0;
    }
    let nodes = i64::try_from(arr.len()).unwrap_or(i64::MAX);
    let mut edges: i64 = 0;
    for block in arr {
        if block.get("jump").and_then(Value::as_u64).is_some() {
            edges += 1;
        }
        if block.get("fail").and_then(Value::as_u64).is_some() {
            edges += 1;
        }
    }
    edges - nodes + 2
}

#[must_use]
pub fn shape_basic_blocks(addr: &str, blocks: Value) -> Value {
    let cc = cyclomatic_complexity(&blocks);
    let arr = match blocks {
        Value::Array(a) => a,
        _ => Vec::new(),
    };
    let block_count = arr.len();
    let block_list: Vec<Value> = arr
        .into_iter()
        .map(|b| {
            let baddr = b.get("addr").and_then(Value::as_u64).unwrap_or(0);
            let size = b.get("size").and_then(Value::as_u64).unwrap_or(0);
            let jump = b.get("jump").and_then(Value::as_u64);
            let fail = b.get("fail").and_then(Value::as_u64);
            let inputs = b.get("inputs").and_then(Value::as_u64).unwrap_or(0);
            let outputs = b.get("outputs").and_then(Value::as_u64).unwrap_or(0);
            json!({
                "addr": format!("{baddr:#x}"),
                "size": size,
                "jump": jump.map(|v| format!("{v:#x}")),
                "fail": fail.map(|v| format!("{v:#x}")),
                "inputs": inputs,
                "outputs": outputs,
            })
        })
        .collect();
    json!({
        "function": addr,
        "block_count": block_count,
        "cyclomatic_complexity": cc,
        "blocks": block_list,
    })
}

pub fn shape_function_cfg(addr: &str, raw: &Value) -> Value {
    let func = first_cfg_function(raw);
    let blocks = cfg_blocks(&func);
    let projection = project_cfg_blocks(&blocks);
    let blocks_with_preds = attach_predecessors(projection.blocks, &projection.edges);

    json!({
        "addr": addr,
        "name": func.get("name").and_then(Value::as_str).unwrap_or(""),
        "function_addr": func.get("addr").and_then(Value::as_u64).map(hex_string),
        "size": func.get("size").and_then(Value::as_u64).unwrap_or(0),
        "nargs": func.get("nargs").and_then(Value::as_u64).unwrap_or(0),
        "nlocals": func.get("nlocals").and_then(Value::as_u64).unwrap_or(0),
        "block_count": blocks_with_preds.len(),
        "edge_count": projection.edges.len(),
        "blocks": blocks_with_preds,
        "edges": projection.edges,
    })
}

fn first_cfg_function(raw: &Value) -> Value {
    raw.as_array()
        .and_then(|arr| arr.first())
        .cloned()
        .unwrap_or_else(|| json!({}))
}

fn cfg_blocks(func: &Value) -> Vec<Value> {
    func.get("blocks")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

#[derive(Debug)]
struct CfgProjection {
    blocks: Vec<Value>,
    edges: Vec<Value>,
}

fn project_cfg_blocks(blocks: &[Value]) -> CfgProjection {
    let mut index_by_addr = std::collections::HashMap::new();
    for (idx, block) in blocks.iter().enumerate() {
        if let Some(baddr) = block.get("addr").and_then(Value::as_u64) {
            index_by_addr.insert(baddr, idx);
        }
    }

    let mut edges: Vec<Value> = Vec::new();
    let projected_blocks: Vec<Value> = blocks
        .iter()
        .enumerate()
        .map(|(idx, block)| project_cfg_block(idx, block, &index_by_addr, &mut edges))
        .collect();
    CfgProjection {
        blocks: projected_blocks,
        edges,
    }
}

fn project_cfg_block(
    idx: usize,
    block: &Value,
    index_by_addr: &std::collections::HashMap<u64, usize>,
    edges: &mut Vec<Value>,
) -> Value {
    let baddr = block.get("addr").and_then(Value::as_u64).unwrap_or(0);
    let jump = block.get("jump").and_then(Value::as_u64);
    let fail = block.get("fail").and_then(Value::as_u64);
    let ops = block
        .get("ops")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut successors = cfg_successors(idx, baddr, jump, fail, index_by_addr, edges);
    successors.sort_unstable();
    successors.dedup();

    json!({
        "index": idx,
        "addr": hex_string(baddr),
        "size": block.get("size").and_then(Value::as_u64).unwrap_or(0),
        "jump": hex_opt(jump),
        "fail": hex_opt(fail),
        "op_count": ops.len(),
        "call_count": cfg_call_count(&ops),
        "string_ref_count": cfg_string_ref_count(&ops),
        "successors": successors,
    })
}

fn cfg_call_count(ops: &[Value]) -> usize {
    ops.iter()
        .filter(|op| op.get("type").and_then(Value::as_str) == Some("call"))
        .count()
}

fn cfg_string_ref_count(ops: &[Value]) -> usize {
    ops.iter()
        .flat_map(|op| {
            op.get("refs")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
        })
        .filter(|r| {
            matches!(
                r.get("type").and_then(Value::as_str),
                Some("STRN" | "STRING")
            )
        })
        .count()
}

fn cfg_successors(
    idx: usize,
    from_addr: u64,
    jump: Option<u64>,
    fail: Option<u64>,
    index_by_addr: &std::collections::HashMap<u64, usize>,
    edges: &mut Vec<Value>,
) -> Vec<usize> {
    let mut successors = Vec::new();
    for (kind, target) in [("jump", jump), ("fail", fail)] {
        if let Some(target) = target
            && let Some(&to_idx) = index_by_addr.get(&target)
        {
            successors.push(to_idx);
            edges.push(json!({
                "from_index": idx,
                "to_index": to_idx,
                "from": hex_string(from_addr),
                "to": hex_string(target),
                "kind": kind,
            }));
        }
    }
    successors
}

fn attach_predecessors(projected_blocks: Vec<Value>, edges: &[Value]) -> Vec<Value> {
    let mut predecessor_map: std::collections::HashMap<usize, Vec<usize>> =
        std::collections::HashMap::new();
    for edge in edges {
        let from = edge
            .get("from_index")
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            .unwrap_or(0);
        let to = edge
            .get("to_index")
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            .unwrap_or(0);
        predecessor_map.entry(to).or_default().push(from);
    }

    projected_blocks
        .into_iter()
        .map(|mut block| {
            if let Some(obj) = block.as_object_mut() {
                let idx = obj
                    .get("index")
                    .and_then(Value::as_u64)
                    .and_then(|value| usize::try_from(value).ok())
                    .unwrap_or(0);
                let mut preds = predecessor_map.remove(&idx).unwrap_or_default();
                preds.sort_unstable();
                preds.dedup();
                obj.insert("predecessors".to_string(), json!(preds));
            }
            block
        })
        .collect()
}

pub fn shape_function_refs(addr: &str, raw: &Value) -> Value {
    let refs = raw.as_array().cloned().unwrap_or_default();
    let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut targets: std::collections::HashMap<String, std::collections::HashSet<u64>> =
        std::collections::HashMap::new();

    for item in &refs {
        let ty = item
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("UNKNOWN")
            .to_string();
        *counts.entry(ty.clone()).or_default() += 1;
        if let Some(target) = item.get("to").and_then(Value::as_u64) {
            targets.entry(ty).or_default().insert(target);
        }
    }

    let mut counts_vec: Vec<_> = counts.into_iter().collect();
    counts_vec.sort_by(|a, b| a.0.cmp(&b.0));
    let type_counts: Vec<Value> = counts_vec
        .into_iter()
        .map(|(ty, count)| json!({ "type": ty, "count": count }))
        .collect();

    let mut targets_vec: Vec<_> = targets.into_iter().collect();
    targets_vec.sort_by(|a, b| a.0.cmp(&b.0));
    let target_groups: Vec<Value> = targets_vec
        .into_iter()
        .map(|(ty, set)| {
            let mut sorted_set: Vec<_> = set.into_iter().collect();
            sorted_set.sort_unstable();
            let preview: Vec<String> = sorted_set
                .iter()
                .take(12)
                .copied()
                .map(hex_string)
                .collect();
            json!({
                "type": ty,
                "target_count": sorted_set.len(),
                "targets_preview": preview,
                "targets_truncated": sorted_set.len() > 12,
            })
        })
        .collect();

    json!({
        "addr": addr,
        "total_ref_count": refs.len(),
        "ref_type_count": type_counts.len(),
        "ref_type_counts": type_counts,
        "target_group_count": target_groups.len(),
        "target_groups": target_groups,
    })
}

fn hex_string(value: u64) -> String {
    format!("{value:#x}")
}

fn hex_opt(value: Option<u64>) -> Value {
    value.map(hex_string).map_or(Value::Null, Value::String)
}

fn project_ref(item: &Value) -> Value {
    json!({
        "addr": item.get("addr").and_then(Value::as_u64).map(hex_string),
        "type": item.get("type").and_then(Value::as_str),
        "perm": item.get("perm").and_then(Value::as_str),
    })
}

pub fn project_disassembly_op(op: &Value) -> Value {
    let refs = op
        .get("refs")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let xrefs = op
        .get("xrefs")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let refs_preview: Vec<Value> = refs.iter().take(4).map(project_ref).collect();
    let xrefs_preview: Vec<Value> = xrefs.iter().take(4).map(project_ref).collect();

    json!({
        "addr": op.get("addr").and_then(Value::as_u64).map(hex_string),
        "size": op.get("size").and_then(Value::as_u64).unwrap_or(0),
        "bytes": op.get("bytes").and_then(Value::as_str).unwrap_or(""),
        "disasm": op.get("disasm").and_then(Value::as_str).unwrap_or(""),
        "opcode": op.get("opcode").and_then(Value::as_str).unwrap_or(""),
        "type": op.get("type").and_then(Value::as_str).unwrap_or(""),
        "family": op.get("family").and_then(Value::as_str).unwrap_or(""),
        "jump": hex_opt(op.get("jump").and_then(Value::as_u64)),
        "fail": hex_opt(op.get("fail").and_then(Value::as_u64)),
        "reloc": op.get("reloc").and_then(Value::as_bool).unwrap_or(false),
        "flags": op.get("flags").cloned().unwrap_or_else(|| json!([])),
        "refs_count": refs.len(),
        "refs_preview": refs_preview,
        "xrefs_count": xrefs.len(),
        "xrefs_preview": xrefs_preview,
    })
}

pub fn shape_disassembly_range(addr: &str, raw: &Value) -> Value {
    let ops = raw.as_array().cloned().unwrap_or_default();
    let projected: Vec<Value> = ops.iter().map(project_disassembly_op).collect();
    json!({
        "addr": addr,
        "instruction_count": projected.len(),
        "ops": projected,
    })
}

pub fn shape_disassembly_function(addr: &str, raw: &Value) -> Value {
    let ops = raw
        .get("ops")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let projected: Vec<Value> = ops.iter().map(project_disassembly_op).collect();
    json!({
        "addr": addr,
        "name": raw.get("name").and_then(Value::as_str).unwrap_or(""),
        "function_addr": raw.get("addr").and_then(Value::as_u64).map(hex_string),
        "size": raw.get("size").and_then(Value::as_u64).unwrap_or(0),
        "instruction_count": projected.len(),
        "ops": projected,
    })
}

/// Decompile the containing function with available r2 decompiler backends.
///
/// # Errors
///
/// Returns an error if the address is invalid or if an r2 command fails.
pub async fn decompile(session: &Session, addr: &str) -> ToolResult<String> {
    validate_addr(addr)?;
    if !session_has_any_decompiler(session).await? {
        return Err(ToolError::invalid(
            "No r2 decompiler plugin available. Install r2ghidra (r2pm -ci r2ghidra) or r2dec (r2pm -ci r2dec), or use r2_decompile mode=meta for compact pdgj metadata.",
        ));
    }
    let pdg = session.cmd(format!("pdg @ {addr}")).await?;
    if !pdg.contains("Cannot") && is_meaningful_decompile_output(&pdg) {
        return Ok(pdg);
    }
    let pdd = session.cmd(format!("pdd @ {addr}")).await?;
    if is_meaningful_decompile_output(&pdd) {
        return Ok(pdd);
    }
    Ok(format!(
        "Decompilation unavailable at {addr}. Install a radare2 decompiler plugin such as r2ghidra (r2pm -ci r2ghidra) or r2dec (r2pm -ci r2dec), or call r2_decompile with mode=meta for compact pdgj metadata. pdg said: {} pdd said: {}",
        one_line_decompiler_reason(&pdg),
        one_line_decompiler_reason(&pdd),
    ))
}

/// Return metadata from r2's JSON decompiler projection.
///
/// # Errors
///
/// Returns an error if the address is invalid or the r2 command fails.
pub async fn decompile_meta(session: &Session, addr: &str) -> ToolResult<Value> {
    validate_addr(addr)?;
    let raw = session.cmd(format!("pdgj @ {addr}")).await?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(shape_unavailable_decompile_meta(
            addr,
            "pdgj returned no output",
        ));
    }
    serde_json::from_str::<Value>(trimmed).map_or_else(
        |_| Ok(shape_unavailable_decompile_meta(addr, trimmed)),
        |raw| Ok(shape_decompile_meta(addr, &raw)),
    )
}

#[must_use]
pub fn is_meaningful_decompile_output(text: &str) -> bool {
    let trimmed = text.trim();
    trimmed.len() > 10 && !is_decompiler_unavailable_message(trimmed)
}

fn is_decompiler_unavailable_message(text: &str) -> bool {
    let lowered = text.to_ascii_lowercase();
    lowered.contains("you need to install the plugin")
        || lowered.contains("r2pm -ci r2ghidra")
        || lowered.contains("r2pm -ci r2dec")
        || lowered.contains("cannot decompile")
        || lowered.contains("decompiler not found")
}

fn one_line_decompiler_reason(text: &str) -> String {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return "no output".to_string();
    }
    trimmed
        .lines()
        .next()
        .unwrap_or(trimmed)
        .chars()
        .take(220)
        .collect()
}

/// Check if any r2 decompiler plugin is installed.
///
/// Runs `LDq` to list decompiler plugins and returns `true` if at least one
/// is registered, `false` otherwise. This avoids wasted `pdg`/`pdd` calls
/// that would return confusing "plugin not installed" messages as text.
async fn session_has_any_decompiler(session: &Session) -> ToolResult<bool> {
    let raw = session.cmd("LDq").await?;
    Ok(raw.lines().any(|line| !line.trim().is_empty()))
}

#[allow(clippy::too_many_lines)]
pub fn shape_decompile_meta(addr: &str, raw: &Value) -> Value {
    let code = raw
        .get("code")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let annotations = raw
        .get("annotations")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut annotation_type_counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    let mut function_refs: std::collections::HashMap<(String, u64), usize> =
        std::collections::HashMap::new();
    let mut global_refs: std::collections::HashMap<u64, usize> = std::collections::HashMap::new();
    let mut local_variables: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut function_parameters: std::collections::HashSet<String> =
        std::collections::HashSet::new();

    for ann in &annotations {
        let ty = ann
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        *annotation_type_counts.entry(ty.clone()).or_default() += 1;

        match ty.as_str() {
            "function_name" => {
                let name = ann
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let offset = ann.get("offset").and_then(Value::as_u64).unwrap_or(0);
                if !name.is_empty() && offset != 0 {
                    *function_refs.entry((name, offset)).or_default() += 1;
                }
            }
            "global_variable" | "constant_variable" => {
                if let Some(offset) = ann.get("offset").and_then(Value::as_u64) {
                    *global_refs.entry(offset).or_default() += 1;
                }
            }
            "local_variable" => {
                if let Some(name) = ann.get("name").and_then(Value::as_str)
                    && !name.is_empty()
                {
                    local_variables.insert(name.to_string());
                }
            }
            "function_parameter" => {
                if let Some(name) = ann.get("name").and_then(Value::as_str)
                    && !name.is_empty()
                {
                    function_parameters.insert(name.to_string());
                }
            }
            _ => {}
        }
    }

    let mut annotation_type_counts_vec: Vec<_> = annotation_type_counts.into_iter().collect();
    annotation_type_counts_vec.sort_by(|a, b| a.0.cmp(&b.0));
    let annotation_type_counts: Vec<Value> = annotation_type_counts_vec
        .into_iter()
        .map(|(name, count)| json!({ "type": name, "count": count }))
        .collect();

    let mut function_refs_vec: Vec<_> = function_refs.into_iter().collect();
    function_refs_vec.sort_by(|a, b| a.0.cmp(&b.0));
    let function_refs: Vec<Value> = function_refs_vec
        .into_iter()
        .map(|((name, offset), count)| {
            json!({ "name": name, "offset": hex_string(offset), "count": count })
        })
        .collect();

    let mut global_refs_vec: Vec<_> = global_refs.into_iter().collect();
    global_refs_vec.sort_unstable_by_key(|k| k.0);
    let global_refs: Vec<Value> = global_refs_vec
        .into_iter()
        .map(|(offset, count)| json!({ "offset": hex_string(offset), "count": count }))
        .collect();

    let mut local_variables: Vec<String> = local_variables.into_iter().collect();
    local_variables.sort_unstable();
    let mut function_parameters: Vec<String> = function_parameters.into_iter().collect();
    function_parameters.sort_unstable();

    json!({
        "addr": addr,
        "available": true,
        "unavailable_reason": "",
        "code_length": code.len(),
        "line_count": code.lines().count(),
        "annotation_count": annotations.len(),
        "annotation_type_count": annotation_type_counts.len(),
        "annotation_types": annotation_type_counts,
        "function_ref_count": function_refs.len(),
        "function_refs": function_refs,
        "global_ref_count": global_refs.len(),
        "global_refs": global_refs,
        "local_variable_count": local_variables.len(),
        "local_variables": local_variables,
        "function_parameter_count": function_parameters.len(),
        "function_parameters": function_parameters,
    })
}

#[must_use]
pub fn shape_unavailable_decompile_meta(addr: &str, reason: &str) -> Value {
    json!({
        "addr": addr,
        "available": false,
        "unavailable_reason": reason,
        "code_length": 0,
        "line_count": 0,
        "annotation_count": 0,
        "annotation_type_count": 0,
        "annotation_types": [],
        "function_ref_count": 0,
        "function_refs": [],
        "global_ref_count": 0,
        "global_refs": [],
        "local_variable_count": 0,
        "local_variables": [],
        "function_parameter_count": 0,
        "function_parameters": [],
    })
}

/// Return direct call targets for the containing function.
///
/// # Errors
///
/// Returns an error if the address is invalid, or if any r2 command used to
/// discover and name callees fails.
pub async fn callees(session: &Session, addr: &str) -> ToolResult<Value> {
    validate_addr(addr)?;
    let func_info = session.cmdj(format!("afij @ {addr}")).await?;
    let Some(f) = first_function(func_info) else {
        return Ok(json!([]));
    };
    let start = f
        .get("offset")
        .or_else(|| f.get("addr"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let size = f.get("size").and_then(Value::as_u64).unwrap_or(0);
    if start == 0 || size == 0 {
        return Ok(json!([]));
    }
    let refs = session.cmdj(format!("afxj @ {addr}")).await?;
    let mut out: Vec<Value> = Vec::new();
    for (target, ty) in extract_callee_targets(&refs) {
        let name_raw = session.cmd(format!("fd @ {target:#x}")).await?;
        let name = name_raw.trim();
        let name_value = if name.is_empty() {
            Value::Null
        } else {
            Value::String(name.to_string())
        };
        out.push(json!({
            "addr": format!("{target:#x}"),
            "name": name_value,
            "type": ty,
        }));
    }
    Ok(Value::Array(out))
}

pub fn extract_callee_targets(refs: &Value) -> Vec<(u64, String)> {
    let Some(arr) = refs.as_array() else {
        return Vec::new();
    };
    let mut seen: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let mut out: Vec<(u64, String)> = Vec::new();
    for r in arr {
        let ty = r.get("type").and_then(Value::as_str).unwrap_or("");
        if ty != "CALL" {
            continue;
        }
        let target = r
            .get("ref")
            .or_else(|| r.get("to"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        if target == 0 || !seen.insert(target) {
            continue;
        }
        out.push((target, ty.to_string()));
    }
    out
}

/// Return normalized xrefs to or from an address.
///
/// # Errors
///
/// Returns an error if the address is invalid, the r2 command fails, or the
/// response is not valid JSON.
pub async fn xrefs(session: &Session, addr: &str, direction: XrefDir) -> ToolResult<Value> {
    validate_addr(addr)?;
    let cmd = match direction {
        XrefDir::To => format!("axtj @ {addr}"),
        XrefDir::From => format!("axfj @ {addr}"),
    };
    let raw = session.cmdj(cmd).await?;
    Ok(project_xrefs(&raw))
}

/// Return metadata for the function containing an address.
///
/// # Errors
///
/// Returns an error if the address is invalid, the r2 command fails, or the
/// response is not valid JSON. If no containing function is found, returns a
/// compact error object with suggested follow-up tools.
pub async fn function_info(session: &Session, addr: &str) -> ToolResult<Value> {
    validate_addr(addr)?;
    let raw = session.cmdj(format!("afij @ {addr}")).await?;
    let Some(func) = first_function(raw) else {
        return Ok(missing_function_response(addr));
    };
    Ok(project_function_info(func))
}

#[must_use]
pub fn project_xrefs(value: &Value) -> Value {
    let Some(arr) = value.as_array() else {
        return json!([]);
    };
    let projected: Vec<Value> = arr
        .iter()
        .map(|item| {
            json!({
                "from": item.get("from").and_then(Value::as_u64).map(hex_string),
                "to": item
                    .get("to")
                    .or_else(|| item.get("ref"))
                    .and_then(Value::as_u64)
                    .map(hex_string),
                "type": item.get("type").and_then(Value::as_str).unwrap_or(""),
                "perm": item.get("perm").and_then(Value::as_str).unwrap_or(""),
                "opcode": item.get("opcode").and_then(Value::as_str).unwrap_or(""),
                "function": item.get("fcn_name").and_then(Value::as_str),
                "function_addr": item.get("fcn_addr").and_then(Value::as_u64).map(hex_string),
                "flag": item.get("flag").and_then(Value::as_str),
                "refname": item.get("refname").and_then(Value::as_str),
                "realname": item.get("realname").and_then(Value::as_str),
            })
        })
        .collect();
    Value::Array(projected)
}

pub fn project_function_info(value: Value) -> Value {
    let Value::Object(mut obj) = value else {
        return value;
    };
    if !obj.contains_key("offset") {
        let offset = obj
            .get("offset")
            .and_then(Value::as_u64)
            .or_else(|| obj.get("addr").and_then(Value::as_u64))
            .or_else(|| obj.get("minaddr").and_then(Value::as_u64));
        if let Some(offset) = offset {
            obj.insert("offset".to_string(), json!(offset));
        }
    }
    Value::Object(obj)
}

/// Return normalized local-variable metadata for a function.
///
/// # Errors
///
/// Returns an error if the address is invalid, the r2 command fails, or the
/// response is not valid JSON.
pub async fn function_vars(session: &Session, addr: &str) -> ToolResult<Value> {
    validate_addr(addr)?;
    let raw = session.cmdj(format!("afvj @ {addr}")).await?;
    Ok(project_function_vars(addr, &raw))
}

pub fn project_function_vars(addr: &str, raw: &Value) -> Value {
    let reg = raw
        .get("reg")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let stack = raw
        .get("sp")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let bp = raw
        .get("bp")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let reg_vars: Vec<Value> = reg
        .iter()
        .map(|item| {
            json!({
                "name": item.get("name").and_then(Value::as_str).unwrap_or(""),
                "kind": item.get("kind").and_then(Value::as_str).unwrap_or(""),
                "type": item.get("type").and_then(Value::as_str),
                "ref": item.get("ref").and_then(Value::as_str),
            })
        })
        .collect();
    let stack_vars: Vec<Value> = stack.iter().map(project_stack_like_var).collect();
    let bp_vars: Vec<Value> = bp.iter().map(project_stack_like_var).collect();

    json!({
        "addr": addr,
        "register_count": reg_vars.len(),
        "registers": reg_vars,
        "stack_count": stack_vars.len(),
        "stack": stack_vars,
        "base_pointer_count": bp_vars.len(),
        "base_pointer": bp_vars,
    })
}

fn project_stack_like_var(item: &Value) -> Value {
    let reference = item.get("ref").cloned().unwrap_or(Value::Null);
    json!({
        "name": item.get("name").and_then(Value::as_str).unwrap_or(""),
        "kind": item.get("kind").and_then(Value::as_str).unwrap_or(""),
        "type": item.get("type").and_then(Value::as_str),
        "ref": reference,
    })
}

/// Return a compact function signature projection.
///
/// # Errors
///
/// Returns an error if the address is invalid, the r2 command fails, or the
/// response is not valid JSON.
pub async fn function_signature(session: &Session, addr: &str) -> ToolResult<Value> {
    validate_addr(addr)?;
    let raw = session.cmdj(format!("afcfj @ {addr}")).await?;
    Ok(project_function_signature(addr, &raw))
}

pub fn project_function_signature(addr: &str, raw: &Value) -> Value {
    let first = raw
        .as_array()
        .and_then(|arr| arr.first())
        .cloned()
        .unwrap_or_else(|| json!({}));
    let args = first
        .get("args")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let args: Vec<Value> = args
        .into_iter()
        .map(|arg| {
            json!({
                "name": arg.get("name").and_then(Value::as_str).unwrap_or(""),
                "type": arg.get("type").and_then(Value::as_str),
            })
        })
        .collect();
    json!({
        "addr": addr,
        "name": first.get("name").and_then(Value::as_str).unwrap_or(""),
        "return": first.get("return").and_then(Value::as_str),
        "arg_count": first.get("count").and_then(Value::as_u64).unwrap_or(args.len() as u64),
        "args": args,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        normalize_graph_format, normalize_graph_kind, normalize_hash_algorithm, validate_addr,
    };

    #[test]
    fn validate_addr_error_names_mcp_addr_parameter() {
        let err = validate_addr("").expect_err("empty addr should fail");

        assert!(
            err.to_string().contains("parameter named \"addr\""),
            "{err}"
        );
    }

    #[test]
    fn graph_aliases_normalize_to_r2_graph_commands() {
        assert_eq!(normalize_graph_kind("cfg").unwrap(), "function");
        assert_eq!(normalize_graph_kind("agC").unwrap(), "global_callgraph");
        assert_eq!(normalize_graph_format("graphviz").unwrap(), "dot");
        assert_eq!(normalize_graph_format("mmd").unwrap(), "mermaid");
        assert!(normalize_graph_format("gml").is_err());
    }

    #[test]
    fn hash_algorithm_defaults_and_rejects_unknown_values() {
        assert_eq!(normalize_hash_algorithm("").unwrap(), "sha256");
        assert_eq!(normalize_hash_algorithm("entropy").unwrap(), "entropy");
        assert!(normalize_hash_algorithm("ssdeep").is_err());
    }
}
