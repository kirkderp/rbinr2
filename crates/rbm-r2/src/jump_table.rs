use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::sync::OnceLock;

use rbm_core::{ToolError, ToolResult};
use regex::Regex;
use serde_json::{Value, json};

use crate::disasm::validate_addr;
use crate::session::Session;

const MAX_ENTRIES: u32 = 256;
const DEFAULT_TARGET_BYTES: u64 = 0x200;
const DEFAULT_MAX_INSTRUCTIONS: u32 = 120;

/// Read jump-table entries and summarize target slices.
///
/// # Errors
///
/// Returns an error if the table address or pointer size is invalid, if an r2
/// command fails, or if the byte table response is not an r2 byte array.
pub async fn jump_table_slices(
    session: &Session,
    table_addr: &str,
    entry_count: u32,
    pointer_size: u32,
    target_bytes: u64,
    max_instructions: u32,
) -> ToolResult<Value> {
    validate_addr(table_addr)?;
    let count = entry_count.clamp(1, MAX_ENTRIES);
    let ptr_size = match pointer_size {
        0 => 4,
        1 | 2 | 4 | 8 => pointer_size,
        other => {
            return Err(ToolError::invalid(format!(
                "pointer_size must be 1, 2, 4, or 8 bytes, got {other}"
            )));
        }
    };
    let target_bytes = if target_bytes == 0 {
        DEFAULT_TARGET_BYTES
    } else {
        target_bytes.min(0x4000)
    };
    let max_instructions = if max_instructions == 0 {
        DEFAULT_MAX_INSTRUCTIONS
    } else {
        max_instructions.min(512)
    };

    let raw = session
        .cmdj(format!("pxj {} @ {table_addr}", count * ptr_size))
        .await?;
    let bytes = bytes_from_pxj(&raw)?;
    let entries = parse_entries(&bytes, count, ptr_size, table_addr);
    let mut unique_targets = BTreeSet::new();
    for entry in &entries {
        unique_targets.insert(entry.target);
    }

    let mut slices = Vec::new();
    for target in unique_targets {
        let instr_count = instructions_for_window(target_bytes, max_instructions);
        let ops = session
            .cmdj(format!("pdj {instr_count} @ {target:#x}"))
            .await?;
        let ops = match ops {
            Value::Array(arr) => arr,
            _ => Vec::new(),
        };
        slices.push(summarize_target(target, &ops, target_bytes));
    }

    let entry_values: Vec<Value> = entries
        .into_iter()
        .map(|entry| {
            json!({
                "index": entry.index,
                "entry_address": format!("{:#x}", entry.address),
                "target_address": format!("{:#x}", entry.target),
                "bytes": entry.bytes,
            })
        })
        .collect();

    Ok(json!({
        "schema": "rbm.r2.jump_table_slices.v0",
        "table_addr": table_addr,
        "entry_count": count,
        "pointer_size": ptr_size,
        "target_bytes": target_bytes,
        "max_instructions": max_instructions,
        "entries": entry_values,
        "unique_target_count": slices.len(),
        "targets": slices,
    }))
}

fn bytes_from_pxj(value: &Value) -> ToolResult<Vec<u8>> {
    let arr = value
        .as_array()
        .ok_or_else(|| ToolError::backend("r2", "pxj did not return a byte array"))?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let byte = item
            .as_u64()
            .ok_or_else(|| ToolError::backend("r2", "pxj byte was not numeric"))?;
        out.push(u8::try_from(byte & 0xff).unwrap_or(0));
    }
    Ok(out)
}

#[derive(Debug)]
struct TableEntry {
    index: u32,
    address: u64,
    target: u64,
    bytes: String,
}

fn parse_entries(bytes: &[u8], count: u32, ptr_size: u32, table_addr: &str) -> Vec<TableEntry> {
    let base = parse_addr_u64(table_addr).unwrap_or(0);
    let ptr_size = usize::try_from(ptr_size).unwrap_or(usize::MAX);
    let mut entries = Vec::new();
    for index in 0..count {
        let offset = usize::try_from(index)
            .unwrap_or(usize::MAX)
            .saturating_mul(ptr_size);
        let Some(end) = offset.checked_add(ptr_size) else {
            break;
        };
        if end > bytes.len() {
            break;
        }
        let chunk = &bytes[offset..end];
        let target = chunk
            .iter()
            .enumerate()
            .fold(0u64, |acc, (i, byte)| acc | (u64::from(*byte) << (i * 8)));
        entries.push(TableEntry {
            index,
            address: base.saturating_add(u64::try_from(offset).unwrap_or(u64::MAX)),
            target,
            bytes: hex_bytes(chunk),
        });
    }
    entries
}

pub fn summarize_target(target: u64, ops: &[Value], target_bytes: u64) -> Value {
    let mut calls = Vec::new();
    let mut jumps = Vec::new();
    let mut terminal_jumps = Vec::new();
    let mut constants = BTreeSet::new();
    let mut writes: BTreeMap<String, BTreeMap<i64, u8>> = BTreeMap::new();
    let mut write_rows: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let end = target.saturating_add(target_bytes);
    let mut scanned = 0usize;
    let mut invalid = 0usize;
    let mut first_valid: Option<&Value> = None;
    let mut last_valid: Option<&Value> = None;

    for op in ops {
        let Some(addr) = op.get("addr").and_then(Value::as_u64) else {
            continue;
        };
        if addr >= end {
            break;
        }
        scanned += 1;
        let opcode = text_field(op, "opcode");
        let disasm = text_field(op, "disasm");
        let kind = text_field(op, "type");
        if is_invalid_op(&opcode, &disasm, &kind) {
            invalid += 1;
            continue;
        }
        if first_valid.is_none() {
            first_valid = Some(op);
        }
        last_valid = Some(op);
        collect_constants(&opcode, &mut constants);

        if kind == "call" || opcode.starts_with("call ") {
            calls.push(json!({
                "address": format!("{addr:#x}"),
                "disassembly": nonempty(&disasm, &opcode),
                "target": jump_field(op),
            }));
        }
        if kind.contains("jmp") || opcode.starts_with("jmp ") {
            let row = json!({
                "address": format!("{addr:#x}"),
                "disassembly": nonempty(&disasm, &opcode),
                "target": jump_field(op),
            });
            if opcode.contains('[') {
                jumps.push(row);
            } else {
                terminal_jumps.push(row);
            }
        }
        if kind == "ret" || opcode.starts_with("ret") {
            terminal_jumps.push(json!({
                "address": format!("{addr:#x}"),
                "disassembly": nonempty(&disasm, &opcode),
                "target": Value::Null,
            }));
        }

        if let Some(write) = parse_immediate_write(&opcode) {
            let entry = writes.entry(write.base.clone()).or_default();
            for i in 0..write.size {
                entry.insert(
                    write
                        .offset
                        .saturating_add(i64::try_from(i).unwrap_or(i64::MAX)),
                    u8::try_from((write.value >> (8 * i)) & 0xff).unwrap_or(0),
                );
            }
            write_rows.entry(write.base).or_default().push(format!(
                "{addr:#x} {} ; offset={:#x} size={}",
                nonempty(&disasm, &opcode),
                write.offset,
                write.size
            ));
        }
    }

    let buffers: Vec<Value> = writes
        .into_iter()
        .filter_map(|(base, bytes)| {
            let rows = write_rows.remove(&base).unwrap_or_default();
            buffer_summary(&base, &bytes, rows)
        })
        .collect();

    json!({
        "target_address": format!("{target:#x}"),
        "instruction_count": scanned.saturating_sub(invalid),
        "invalid_instruction_count": invalid,
        "all_instructions_invalid": scanned > 0 && scanned == invalid,
        "raw_instruction_count": scanned,
        "calls": calls,
        "indirect_jumps": jumps,
        "terminal_jumps": terminal_jumps,
        "local_buffers": buffers,
        "constants_preview": constants.into_iter().take(24).collect::<Vec<_>>(),
        "first_instruction": instruction_text(first_valid),
        "last_instruction": instruction_text(last_valid),
        "first_raw_instruction": instruction_text(ops.first()),
        "last_raw_instruction": instruction_text(ops.get(scanned.saturating_sub(1))),
    })
}

fn is_invalid_op(opcode: &str, disasm: &str, kind: &str) -> bool {
    kind == "ill" || opcode == "invalid" || disasm == "invalid"
}

fn instructions_for_window(target_bytes: u64, max_instructions: u32) -> u32 {
    let rough = u32::try_from((target_bytes / 4).max(16))
        .unwrap_or(u32::MAX)
        .min(max_instructions);
    rough.max(16)
}

#[derive(Debug)]
struct ImmediateWrite {
    base: String,
    offset: i64,
    size: usize,
    value: u64,
}

fn parse_immediate_write(opcode: &str) -> Option<ImmediateWrite> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(
            r"(?i)^mov\s+(byte|word|dword|qword)\s+\[([a-z0-9]+)(?:\s*([+-])\s*(0x[0-9a-f]+|\d+))?\],\s*(0x[0-9a-f]+|\d+)$",
        )
        .expect("valid immediate write regex")
    });
    let caps = re.captures(opcode.trim())?;
    let size = match caps.get(1)?.as_str().to_ascii_lowercase().as_str() {
        "byte" => 1,
        "word" => 2,
        "dword" => 4,
        "qword" => 8,
        _ => return None,
    };
    let mut offset = caps.get(4).map_or(0, |m| {
        parse_addr_u64(m.as_str())
            .and_then(|value| i64::try_from(value).ok())
            .unwrap_or(i64::MAX)
    });
    if caps.get(3).is_some_and(|m| m.as_str() == "-") {
        offset = -offset;
    }
    let value = parse_addr_u64(caps.get(5)?.as_str())?;
    Some(ImmediateWrite {
        base: caps.get(2)?.as_str().to_ascii_lowercase(),
        offset,
        size,
        value,
    })
}

fn buffer_summary(base: &str, bytes: &BTreeMap<i64, u8>, writes: Vec<String>) -> Option<Value> {
    if bytes.len() < 2 || bytes.values().all(|b| *b == 0) {
        return None;
    }
    let min = *bytes.keys().next()?;
    let max = *bytes.keys().next_back()?;
    if max - min > 512 {
        return None;
    }
    let contiguous: Vec<u8> = (min..=max)
        .map(|offset| bytes.get(&offset).copied().unwrap_or(0))
        .collect();
    Some(json!({
        "base": base,
        "byte_count": contiguous.len(),
        "min_offset": format!("{min:#x}"),
        "max_offset": format!("{max:#x}"),
        "hex": hex_bytes(&contiguous),
        "ascii_preview": ascii_preview(&contiguous),
        "utf16le_preview": utf16le_preview(&contiguous),
        "writes_preview": writes.into_iter().take(12).collect::<Vec<_>>(),
    }))
}

fn collect_constants(opcode: &str, out: &mut BTreeSet<String>) {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"(?i)\b0x[0-9a-f]{3,16}\b").expect("constant regex"));
    for m in re.find_iter(opcode) {
        let raw = m.as_str().to_ascii_lowercase();
        if !matches!(raw.as_str(), "0xff" | "0xffff" | "0xffffffff") {
            out.insert(raw);
        }
    }
}

fn jump_field(op: &Value) -> Value {
    if let Some(jump) = op.get("jump") {
        if let Some(addr) = jump.as_u64() {
            return Value::String(format!("{addr:#x}"));
        }
        return jump.clone();
    }
    Value::Null
}

fn instruction_text(op: Option<&Value>) -> String {
    let Some(op) = op else {
        return String::new();
    };
    let addr = op.get("addr").and_then(Value::as_u64).unwrap_or(0);
    let opcode = text_field(op, "opcode");
    let disasm = text_field(op, "disasm");
    format!("{addr:#x} {}", nonempty(&disasm, &opcode))
}

fn text_field(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

const fn nonempty<'a>(preferred: &'a str, alternate: &'a str) -> &'a str {
    if preferred.is_empty() {
        alternate
    } else {
        preferred
    }
}

fn parse_addr_u64(value: &str) -> Option<u64> {
    let raw = value.trim();
    raw.strip_prefix("0x")
        .or_else(|| raw.strip_prefix("0X"))
        .map_or_else(
            || raw.parse::<u64>().ok(),
            |hex| u64::from_str_radix(hex, 16).ok(),
        )
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut out, "{byte:02x}").expect("formatting into String cannot fail");
    }
    out
}

fn ascii_preview(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| {
            if (0x20..=0x7e).contains(b) {
                *b as char
            } else {
                '.'
            }
        })
        .collect()
}

fn utf16le_preview(bytes: &[u8]) -> String {
    bytes
        .chunks_exact(2)
        .map(|chunk| {
            let ch = u16::from_le_bytes([chunk[0], chunk[1]]);
            if (0x20..=0x7e).contains(&ch) {
                char::from_u32(u32::from(ch)).unwrap_or('.')
            } else {
                '.'
            }
        })
        .collect()
}
