use std::collections::HashSet;
use std::sync::OnceLock;

use rbm_core::ToolResult;
use serde_json::{Value, json};

use crate::disasm::{
    self, callees, cyclomatic_complexity, first_function, missing_function_response, validate_addr,
};
use crate::session::Session;

/// Return string references originating from a function.
///
/// # Errors
///
/// Returns an error if the address is invalid, if r2 xref metadata is not valid
/// JSON, or if reading a referenced string fails.
pub async fn function_strings(session: &Session, addr: &str) -> ToolResult<Vec<Value>> {
    validate_addr(addr)?;
    let refs = session.cmdj(format!("axfj @ {addr}")).await?;
    let arr = match refs {
        Value::Array(a) => a,
        _ => Vec::new(),
    };
    let mut seen: HashSet<u64> = HashSet::new();
    let mut out: Vec<Value> = Vec::new();
    for r in arr {
        let ty = r.get("type").and_then(Value::as_str).unwrap_or("");
        if ty != "DATA" && ty != "STRING" {
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
        let raw = session.cmd(format!("psz @ {target:#x}")).await?;
        let s = raw.trim();
        if s.len() < 4 {
            continue;
        }
        out.push(json!({
            "addr": format!("{target:#x}"),
            "string": s,
        }));
    }
    Ok(out)
}

/// Extract notable constants from a function disassembly.
///
/// # Errors
///
/// Returns an error if the address is invalid or if the r2 disassembly command
/// fails.
pub async fn function_constants(session: &Session, addr: &str) -> ToolResult<Vec<Value>> {
    validate_addr(addr)?;
    let text = session.cmd(format!("pdf @ {addr}")).await?;
    Ok(extract_constants(&text))
}

#[must_use]
pub fn extract_constants(disasm: &str) -> Vec<Value> {
    let re = hex_regex();
    let boring: HashSet<u64> = [0u64, 1, 0xff, 0xffff, 0xffff_ffff, 0xffff_ffff_ffff_ffff]
        .into_iter()
        .collect();
    let mut seen: HashSet<u64> = HashSet::new();
    let mut out: Vec<u64> = Vec::new();
    for m in re.find_iter(disasm) {
        let raw = m.as_str();
        let stripped = raw.trim_start_matches("0x").trim_start_matches("0X");
        let Ok(val) = u64::from_str_radix(stripped, 16) else {
            continue;
        };
        if boring.contains(&val) || val < 0x100 || !seen.insert(val) {
            continue;
        }
        out.push(val);
    }
    // Use sort_unstable_by to avoid allocations and improve performance
    out.sort_unstable_by(|a, b| b.cmp(a));
    out.truncate(20);
    out.into_iter()
        .map(|val| json!({"value": val, "hex": format!("{val:#x}")}))
        .collect()
}

fn hex_regex() -> &'static regex::Regex {
    static HEX_RE: OnceLock<regex::Regex> = OnceLock::new();
    HEX_RE.get_or_init(|| regex::Regex::new(r"\b0[xX][0-9a-fA-F]+\b").expect("static regex"))
}

#[must_use]
pub const fn classify_function(size: u64, callee_count: usize, _name: &str) -> &'static str {
    if size <= 16 {
        return "thunk";
    }
    if callee_count == 1 && size < 100 {
        return "wrapper";
    }
    if callee_count == 0 {
        return "leaf";
    }
    if callee_count > 10 {
        return "dispatcher";
    }
    "complex"
}

/// Return a compact structural profile for a function.
///
/// # Errors
///
/// Returns an error if the address is invalid, if any required r2 command fails,
/// or if required r2 JSON output cannot be decoded.
pub async fn func_profile(session: &Session, addr: &str) -> ToolResult<Value> {
    validate_addr(addr)?;
    let raw_func = session.cmdj(format!("afij @ {addr}")).await?;
    let Some(func) = first_function(raw_func) else {
        return Ok(missing_function_response(addr));
    };

    let blocks_raw = session.cmdj(format!("afbj @ {addr}")).await?;
    let cc = cyclomatic_complexity(&blocks_raw);
    let block_arr = match blocks_raw {
        Value::Array(a) => a,
        _ => Vec::new(),
    };
    let block_count = block_arr.len();
    let insn_count: u64 = block_arr
        .iter()
        .map(|b| {
            b.get("ninstr")
                .and_then(Value::as_u64)
                .unwrap_or_else(|| b.get("size").and_then(Value::as_u64).unwrap_or(0) / 4)
        })
        .sum();

    let callers = disasm::xrefs(session, addr, disasm::XrefDir::To).await?;
    let incoming_call_count = callers.as_array().map_or(0, std::vec::Vec::len);

    let callees_value = callees(session, addr).await?;
    let outgoing_call_count = callees_value.as_array().map_or(0, std::vec::Vec::len);

    let strings = function_strings(session, addr).await?;
    let string_ref_count = strings.len();

    let constants = function_constants(session, addr).await?;
    let constant_count = constants.len();

    let size = func.get("size").and_then(Value::as_u64).unwrap_or(0);
    let name = func.get("name").and_then(Value::as_str).unwrap_or("");
    let offset = func
        .get("offset")
        .or_else(|| func.get("addr"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let classification = classify_function(size, outgoing_call_count, name);

    Ok(json!({
        "addr": format!("{offset:#x}"),
        "name": name,
        "size": size,
        "instruction_count": insn_count,
        "basic_block_count": block_count,
        "cyclomatic_complexity": cc,
        "caller_count": incoming_call_count,
        "callee_count": outgoing_call_count,
        "string_ref_count": string_ref_count,
        "constant_count": constant_count,
        "classification": classification,
    }))
}
