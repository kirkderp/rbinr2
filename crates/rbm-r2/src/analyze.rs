use rbm_core::ToolResult;
use serde_json::{Value, json};

use crate::disasm::{
    self, callees, cyclomatic_complexity, decompile, decompile_meta, disassemble_function,
    first_function, function_refs, missing_function_response, validate_addr,
};
use crate::func_profile::{function_constants, function_strings};
use crate::session::Session;

const MAX_NEIGHBOURS: usize = 30;

/// Build a compact function analysis summary from r2 projections.
///
/// # Errors
///
/// Returns an error if the address is unsafe for r2 command interpolation, if an
/// r2 command fails, or if a required JSON projection cannot be decoded.
pub async fn analyze_function(
    session: &Session,
    addr: &str,
    include_asm: bool,
) -> ToolResult<Value> {
    validate_addr(addr)?;

    let raw_func = session.cmdj(format!("afij @ {addr}")).await?;
    let Some(func) = first_function(raw_func) else {
        return Ok(missing_function_response(addr));
    };

    let name = func
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let offset = func.get("offset").and_then(Value::as_u64).unwrap_or(0);
    let size = func.get("size").and_then(Value::as_u64).unwrap_or(0);

    let decompiled = decompile(session, addr).await.ok();
    let decompile_meta = decompile_meta(session, addr).await.ok();

    let assembly = if include_asm {
        disassemble_function(session, addr).await.ok()
    } else {
        None
    };

    let strings = function_strings(session, addr).await?;
    let constants = function_constants(session, addr).await?;

    let callers = disasm::xrefs(session, addr, disasm::XrefDir::To).await?;
    let (incoming_preview, incoming_call_count) = trim_neighbours(callers);

    let callees_value = callees(session, addr).await?;
    let (outgoing_preview, outgoing_call_count) = trim_neighbours(callees_value);

    let blocks_raw = session.cmdj(format!("afbj @ {addr}")).await?;
    let cc = cyclomatic_complexity(&blocks_raw);
    let basic_block_count = blocks_raw.as_array().map_or(0, std::vec::Vec::len);
    let cfg_summary = summarize_basic_blocks(&blocks_raw);
    let ref_summary = function_refs(session, addr).await.ok();

    Ok(json!({
        "addr": addr,
        "error": Value::Null,
        "name": name,
        "offset": format!("{offset:#x}"),
        "size": size,
        "decompiled": decompiled,
        "decompile_meta": decompile_meta,
        "assembly": assembly,
        "strings": strings,
        "constants": constants,
        "callers": incoming_preview,
        "caller_count": incoming_call_count,
        "callees": outgoing_preview,
        "callee_count": outgoing_call_count,
        "basic_block_count": basic_block_count,
        "cyclomatic_complexity": cc,
        "cfg_summary": cfg_summary,
        "ref_summary": ref_summary,
    }))
}

#[must_use]
pub fn trim_neighbours(value: Value) -> (Value, usize) {
    match value {
        Value::Array(mut arr) => {
            let count = arr.len();
            if count > MAX_NEIGHBOURS {
                arr.truncate(MAX_NEIGHBOURS);
            }
            (Value::Array(arr), count)
        }
        _ => (Value::Array(Vec::new()), 0),
    }
}

pub fn summarize_basic_blocks(value: &Value) -> Value {
    let Some(blocks) = value.as_array() else {
        return json!({
            "block_count": 0,
            "edge_count": 0,
            "branch_block_count": 0,
            "exit_block_count": 0,
            "call_block_count": 0,
            "string_ref_block_count": 0,
        });
    };

    let mut edge_count = 0usize;
    let mut branch_block_count = 0usize;
    let mut exit_block_count = 0usize;
    let mut call_block_count = 0usize;
    let mut string_ref_block_count = 0usize;

    for block in blocks {
        let jump = block.get("jump").and_then(Value::as_u64);
        let fail = block.get("fail").and_then(Value::as_u64);
        if jump.is_some() {
            edge_count += 1;
        }
        if fail.is_some() {
            edge_count += 1;
        }
        if jump.is_some() && fail.is_some() {
            branch_block_count += 1;
        }
        if jump.is_none() && fail.is_none() {
            exit_block_count += 1;
        }

        let ops = block
            .get("ops")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if ops
            .iter()
            .any(|op| op.get("type").and_then(Value::as_str) == Some("call"))
        {
            call_block_count += 1;
        }
        if ops.iter().any(|op| {
            op.get("refs")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .any(|r| {
                    matches!(
                        r.get("type").and_then(Value::as_str),
                        Some("STRN" | "STRING")
                    )
                })
        }) {
            string_ref_block_count += 1;
        }
    }

    json!({
        "block_count": blocks.len(),
        "edge_count": edge_count,
        "branch_block_count": branch_block_count,
        "exit_block_count": exit_block_count,
        "call_block_count": call_block_count,
        "string_ref_block_count": string_ref_block_count,
    })
}
