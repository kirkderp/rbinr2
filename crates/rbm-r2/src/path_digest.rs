use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::Write as _;
use std::sync::OnceLock;

use rbm_core::{ToolError, ToolResult};
use regex::Regex;
use serde_json::{Value, json};

use crate::disasm::{validate_addr, validate_value};
use crate::session::Session;

const DEFAULT_MAX_INSTRUCTIONS: u32 = 800;
const MAX_INSTRUCTIONS: u32 = 5000;
const DEFAULT_MAX_EVENTS: usize = 80;
const MAX_EVENTS: usize = 1000;

#[derive(Debug, Clone)]
pub struct PathDigestOptions<'a> {
    pub arch: Option<&'a str>,
    pub bits: u32,
    pub range_end: Option<&'a str>,
    pub stop_addresses: Option<&'a str>,
    pub state_register: Option<&'a str>,
    pub marker_constants: Option<&'a str>,
    pub max_instructions: u32,
    pub max_events: usize,
}

/// Scan instructions through r2 and summarize control/path-relevant events.
///
/// # Errors
///
/// Returns an error if addresses, stop addresses, r2 settings, bit width, or
/// marker options are invalid, or if the r2 disassembly command fails.
pub async fn path_digest(
    session: &Session,
    start_addr: &str,
    options: PathDigestOptions<'_>,
) -> ToolResult<Value> {
    validate_addr(start_addr)?;
    if let Some(end) = options.range_end {
        validate_value("range_end", end)?;
    }
    if let Some(stops) = options.stop_addresses {
        validate_stop_addresses(stops)?;
    }
    if let Some(arch) = options.arch {
        validate_r2_setting("arch", arch)?;
    }
    validate_bits(options.bits)?;

    let max_instructions = clamp_instructions(options.max_instructions);
    let snapshot = session
        .apply_asm_settings(options.arch, options.bits)
        .await?;
    let ops_result = session
        .cmdj(format!("pdj {max_instructions} @ {start_addr}"))
        .await;
    session.restore_asm_settings(snapshot).await?;
    let ops = ops_result?;
    let ops = match ops {
        Value::Array(arr) => arr,
        _ => Vec::new(),
    };

    build_path_digest(start_addr, &ops, &options)
}

/// Build a path digest from already-collected r2 instruction objects.
///
/// # Errors
///
/// Returns an error if stop-address, state-register, or marker-constant options
/// are malformed.
pub fn build_path_digest(
    start_addr: &str,
    ops: &[Value],
    options: &PathDigestOptions<'_>,
) -> ToolResult<Value> {
    let config = PathDigestConfig::from_options(options)?;
    let mut collected = collect_path_digest(ops, &config);
    let local_buffers = build_local_buffers(
        std::mem::take(&mut collected.local_writes),
        &mut collected.local_write_rows,
    );
    let constants_preview = constants_preview(std::mem::take(&mut collected.constants));

    Ok(json!({
        "schema": "rbm.r2.path_digest.v0",
        "start_addr": start_addr,
        "range_end": options.range_end,
        "arch": options.arch,
        "bits": options.bits,
        "state_register": config.state_register,
        "instruction_count": collected.scanned,
        "event_count": collected.events.len(),
        "event_truncated": collected.event_truncated,
        "stop_hit": collected.stop_hit,
        "marker_hit_count": collected.marker_hits.len(),
        "marker_hits": collected.marker_hits.into_iter().take(64).collect::<Vec<_>>(),
        "constants_preview": constants_preview,
        "local_buffers": local_buffers,
        "events": collected.events,
    }))
}

fn build_local_buffers(
    local_writes: BTreeMap<String, BTreeMap<i64, u8>>,
    local_write_rows: &mut BTreeMap<String, Vec<String>>,
) -> Vec<Value> {
    local_writes
        .into_iter()
        .filter_map(|(base, bytes)| {
            let rows = local_write_rows.remove(&base).unwrap_or_default();
            summarize_buffer(&base, &bytes, rows)
        })
        .collect()
}

fn constants_preview(constants: BTreeMap<String, ConstantHit>) -> Vec<Value> {
    constants
        .into_values()
        .take(64)
        .map(|hit| {
            json!({
                "value": hit.value,
                "marker": hit.marker,
                "addresses_preview": hit.addresses,
            })
        })
        .collect()
}

struct PathDigestConfig {
    range_end: Option<u64>,
    stop_addresses: BTreeSet<u64>,
    state_register: String,
    markers: BTreeMap<String, String>,
    max_events: usize,
}

impl PathDigestConfig {
    fn from_options(options: &PathDigestOptions<'_>) -> ToolResult<Self> {
        let state_register = options
            .state_register
            .filter(|s| !s.trim().is_empty())
            .unwrap_or("esi")
            .to_ascii_lowercase();
        validate_register_name(&state_register)?;
        Ok(Self {
            range_end: options.range_end.and_then(parse_addr_u64),
            stop_addresses: parse_stop_set(options.stop_addresses.unwrap_or_default())?,
            state_register,
            markers: parse_marker_constants(options.marker_constants.unwrap_or_default())?,
            max_events: clamp_events(options.max_events),
        })
    }
}

struct PathDigestCollected {
    events: Vec<Value>,
    constants: BTreeMap<String, ConstantHit>,
    marker_hits: Vec<Value>,
    local_writes: BTreeMap<String, BTreeMap<i64, u8>>,
    local_write_rows: BTreeMap<String, Vec<String>>,
    event_truncated: bool,
    stop_hit: Option<Value>,
    scanned: usize,
}

struct ControlEventContext<'a> {
    op: &'a Value,
    kind: &'a str,
    opcode: &'a str,
    address: &'a str,
    disasm: &'a str,
    setup_context: &'a VecDeque<String>,
}

fn collect_path_digest(ops: &[Value], config: &PathDigestConfig) -> PathDigestCollected {
    let mut collected = PathDigestCollected {
        events: Vec::new(),
        constants: BTreeMap::new(),
        marker_hits: Vec::new(),
        local_writes: BTreeMap::new(),
        local_write_rows: BTreeMap::new(),
        event_truncated: false,
        stop_hit: None,
        scanned: 0,
    };
    let mut context = VecDeque::with_capacity(8);

    for op in ops {
        let Some(addr) = op.get("addr").and_then(Value::as_u64) else {
            continue;
        };
        if config.range_end.is_some_and(|end| addr >= end) {
            break;
        }
        collect_path_digest_op(op, addr, config, &mut context, &mut collected);
        if collected.stop_hit.is_some() {
            break;
        }
    }

    collected
}

fn collect_path_digest_op(
    op: &Value,
    addr: u64,
    config: &PathDigestConfig,
    context: &mut VecDeque<String>,
    collected: &mut PathDigestCollected,
) {
    collected.scanned += 1;
    let opcode = text_field(op, "opcode");
    let disasm = nonempty(&text_field(op, "disasm"), &opcode).to_string();
    let kind = text_field(op, "type");
    let address = format!("{addr:#x}");

    record_constants(&opcode, &address, &disasm, config, context, collected);
    let control_context = ControlEventContext {
        op,
        kind: &kind,
        opcode: &opcode,
        address: &address,
        disasm: &disasm,
        setup_context: context,
    };
    record_control_event(&control_context, config, collected);
    record_state_write(&opcode, &address, &disasm, config, collected);
    record_immediate_write(&opcode, &address, &disasm, collected);
    update_context(context, &address, &disasm, &opcode);
    if config.stop_addresses.contains(&addr) {
        collected.stop_hit = Some(json!({
            "address": format!("{addr:#x}"),
            "disassembly": disasm,
        }));
    }
}

fn record_constants(
    opcode: &str,
    address: &str,
    disasm: &str,
    config: &PathDigestConfig,
    context: &VecDeque<String>,
    collected: &mut PathDigestCollected,
) {
    for constant in collect_constants(opcode) {
        let hit = collected
            .constants
            .entry(constant.clone())
            .or_insert_with(|| ConstantHit {
                value: constant.clone(),
                marker: config.markers.get(&constant).cloned(),
                addresses: Vec::new(),
            });
        if hit.addresses.len() < 16 {
            hit.addresses.push(address.to_string());
        }
        if let Some(marker) = config.markers.get(&constant) {
            let row = json!({
                "address": address,
                "constant": constant,
                "marker": marker,
                "disassembly": disasm,
                "setup_preview": context_preview(context, 4),
            });
            collected.marker_hits.push(row.clone());
            push_event(
                &mut collected.events,
                &mut collected.event_truncated,
                config.max_events,
                "marker",
                row,
            );
        }
    }
}

fn record_control_event(
    control_context: &ControlEventContext<'_>,
    config: &PathDigestConfig,
    collected: &mut PathDigestCollected,
) {
    let event = if is_call(control_context.kind, control_context.opcode) {
        Some((
            "call",
            json!({
                "address": control_context.address,
                "disassembly": control_context.disasm,
                "target": jump_field(control_context.op),
                "setup_preview": context_preview(control_context.setup_context, 6),
            }),
        ))
    } else if is_jump(control_context.kind, control_context.opcode) {
        Some((
            if is_indirect_jump(control_context.opcode) {
                "indirect_jump"
            } else {
                "jump"
            },
            json!({
                "address": control_context.address,
                "disassembly": control_context.disasm,
                "target": jump_field(control_context.op),
                "fallthrough": fall_field(control_context.op),
            }),
        ))
    } else if control_context.kind == "ret" || control_context.opcode.starts_with("ret") {
        Some((
            "return",
            json!({
                "address": control_context.address,
                "disassembly": control_context.disasm,
            }),
        ))
    } else {
        None
    };
    if let Some((event_kind, row)) = event {
        push_event(
            &mut collected.events,
            &mut collected.event_truncated,
            config.max_events,
            event_kind,
            row,
        );
    }
}

fn record_state_write(
    opcode: &str,
    address: &str,
    disasm: &str,
    config: &PathDigestConfig,
    collected: &mut PathDigestCollected,
) {
    if let Some(write) = parse_state_write(opcode, &config.state_register) {
        push_event(
            &mut collected.events,
            &mut collected.event_truncated,
            config.max_events,
            "state_write",
            json!({
                "address": address,
                "disassembly": disasm,
                "register": config.state_register,
                "offset": format_signed_hex(write.offset),
                "operation": write.operation,
                "value": write.value,
            }),
        );
    }
}

fn record_immediate_write(
    opcode: &str,
    address: &str,
    disasm: &str,
    collected: &mut PathDigestCollected,
) {
    if let Some(write) = parse_immediate_write(opcode) {
        let entry = collected
            .local_writes
            .entry(write.base.clone())
            .or_default();
        for i in 0..write.size {
            entry.insert(
                write
                    .offset
                    .saturating_add(i64::try_from(i).unwrap_or(i64::MAX)),
                u8::try_from((write.value >> (8 * i)) & 0xff).unwrap_or(0),
            );
        }
        collected
            .local_write_rows
            .entry(write.base)
            .or_default()
            .push(format!("{address} {disasm}"));
    }
}

#[derive(Debug)]
struct ConstantHit {
    value: String,
    marker: Option<String>,
    addresses: Vec<String>,
}

#[derive(Debug)]
struct StateWrite {
    offset: i64,
    operation: String,
    value: Option<String>,
}

#[derive(Debug)]
struct ImmediateWrite {
    base: String,
    offset: i64,
    size: usize,
    value: u64,
}

/// Parse marker constants from `value=name` entries.
///
/// # Errors
///
/// Returns an error if an entry is missing a separator, has a nonnumeric value,
/// or contains an invalid marker name.
pub fn parse_marker_constants(input: &str) -> ToolResult<BTreeMap<String, String>> {
    let mut markers = BTreeMap::new();
    for raw in input.split([',', '\n']) {
        let item = raw.trim();
        if item.is_empty() {
            continue;
        }
        let (value, name) = item
            .split_once('=')
            .or_else(|| item.split_once(':'))
            .ok_or_else(|| {
                ToolError::invalid(format!(
                    "marker constants must use value=name entries, got {item:?}"
                ))
            })?;
        let Some(parsed) = parse_addr_u64(value.trim()) else {
            return Err(ToolError::invalid(format!(
                "marker constant value is not numeric: {value:?}"
            )));
        };
        let name = name.trim();
        validate_symbol_name("marker name", name)?;
        markers.insert(format!("{parsed:#x}"), name.to_string());
    }
    Ok(markers)
}

fn validate_stop_addresses(input: &str) -> ToolResult<()> {
    for raw in input.split([',', ' ', '\n', '\t']) {
        let item = raw.trim();
        if item.is_empty() {
            continue;
        }
        validate_addr(item)?;
    }
    Ok(())
}

fn parse_stop_set(input: &str) -> ToolResult<BTreeSet<u64>> {
    let mut out = BTreeSet::new();
    for raw in input.split([',', ' ', '\n', '\t']) {
        let item = raw.trim();
        if item.is_empty() {
            continue;
        }
        let Some(addr) = parse_addr_u64(item) else {
            return Err(ToolError::invalid(format!(
                "stop address is not numeric: {item:?}"
            )));
        };
        out.insert(addr);
    }
    Ok(out)
}

fn validate_r2_setting(label: &str, value: &str) -> ToolResult<()> {
    if value.is_empty()
        || !value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    {
        return Err(ToolError::invalid(format!("invalid r2 {label}: {value:?}")));
    }
    Ok(())
}

fn validate_bits(bits: u32) -> ToolResult<()> {
    match bits {
        0 | 8 | 16 | 32 | 64 => Ok(()),
        other => Err(ToolError::invalid(format!(
            "bits must be one of 0, 8, 16, 32, 64; got {other}"
        ))),
    }
}

fn validate_register_name(register: &str) -> ToolResult<()> {
    if register
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        Ok(())
    } else {
        Err(ToolError::invalid(format!(
            "state_register must be a register-like token, got {register:?}"
        )))
    }
}

fn validate_symbol_name(label: &str, value: &str) -> ToolResult<()> {
    if !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    {
        Ok(())
    } else {
        Err(ToolError::invalid(format!(
            "{label} must be a simple symbol token, got {value:?}"
        )))
    }
}

fn clamp_instructions(value: u32) -> u32 {
    if value == 0 {
        DEFAULT_MAX_INSTRUCTIONS
    } else {
        value.min(MAX_INSTRUCTIONS)
    }
}

fn clamp_events(value: usize) -> usize {
    if value == 0 {
        DEFAULT_MAX_EVENTS
    } else {
        value.min(MAX_EVENTS)
    }
}

fn push_event(
    events: &mut Vec<Value>,
    truncated: &mut bool,
    max_events: usize,
    kind: &str,
    mut body: Value,
) {
    if events.len() >= max_events {
        *truncated = true;
        return;
    }
    if let Value::Object(ref mut map) = body {
        map.insert("kind".to_string(), Value::String(kind.to_string()));
    }
    events.push(body);
}

fn update_context(context: &mut VecDeque<String>, address: &str, disasm: &str, opcode: &str) {
    if is_setup_instruction(opcode) {
        if context.len() == 8 {
            context.pop_front();
        }
        context.push_back(format!("{address} {disasm}"));
    }
}

fn context_preview(context: &VecDeque<String>, limit: usize) -> Vec<String> {
    context
        .iter()
        .rev()
        .take(limit)
        .cloned()
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect()
}

fn is_setup_instruction(opcode: &str) -> bool {
    let lower = opcode.trim().to_ascii_lowercase();
    lower.starts_with("push ")
        || lower.starts_with("lea ")
        || lower.starts_with("mov ")
        || lower.starts_with("xor ")
        || lower.starts_with("add ")
        || lower.starts_with("sub ")
}

fn is_call(kind: &str, opcode: &str) -> bool {
    kind == "call" || opcode.trim_start().starts_with("call ")
}

fn is_jump(kind: &str, opcode: &str) -> bool {
    kind.contains("jmp") || opcode.trim_start().starts_with('j')
}

fn is_indirect_jump(opcode: &str) -> bool {
    let lower = opcode.to_ascii_lowercase();
    lower.starts_with("jmp ") && (lower.contains('[') || !lower.contains("0x"))
}

fn parse_state_write(opcode: &str, state_register: &str) -> Option<StateWrite> {
    let escaped = regex::escape(state_register);
    let re = Regex::new(&format!(
        r"(?i)^(mov|lea|add|sub|xor|and|or|inc|dec)\s+(?:byte|word|dword|qword)?\s*\[{escaped}(?:\s*([+-])\s*(0x[0-9a-f]+|\d+))?\],\s*([^;]+)$"
    ))
    .ok()?;
    let caps = re.captures(opcode.trim())?;
    let mut offset = caps.get(3).map_or(0, |m| {
        parse_addr_u64(m.as_str())
            .and_then(|value| i64::try_from(value).ok())
            .unwrap_or(i64::MAX)
    });
    if caps.get(2).is_some_and(|m| m.as_str() == "-") {
        offset = -offset;
    }
    Some(StateWrite {
        offset,
        operation: caps.get(1)?.as_str().to_ascii_lowercase(),
        value: caps.get(4).map(|m| m.as_str().trim().to_string()),
    })
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

fn summarize_buffer(base: &str, bytes: &BTreeMap<i64, u8>, writes: Vec<String>) -> Option<Value> {
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

fn collect_constants(opcode: &str) -> BTreeSet<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"(?i)\b0x[0-9a-f]{3,16}\b").expect("constant regex"));
    re.find_iter(opcode)
        .filter_map(|m| parse_addr_u64(m.as_str()).map(|value| format!("{value:#x}")))
        .filter(|value| !matches!(value.as_str(), "0xff" | "0xffff" | "0xffffffff"))
        .collect()
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

fn fall_field(op: &Value) -> Value {
    if let Some(fail) = op.get("fail") {
        if let Some(addr) = fail.as_u64() {
            return Value::String(format!("{addr:#x}"));
        }
        return fail.clone();
    }
    Value::Null
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

fn format_signed_hex(value: i64) -> String {
    if value < 0 {
        format!("-{:#x}", value.unsigned_abs())
    } else {
        format!("{value:#x}")
    }
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

#[cfg(test)]
mod tests {
    use super::{parse_marker_constants, validate_bits};

    #[test]
    fn bits_zero_uses_r2_default() {
        assert!(validate_bits(0).is_ok());
        assert!(validate_bits(32).is_ok());
        assert!(validate_bits(7).is_err());
    }

    #[test]
    fn marker_constants_reject_non_symbol_names() {
        assert!(parse_marker_constants("0x1234=good.marker-1").is_ok());
        assert!(parse_marker_constants("0x1234=bad marker").is_err());
    }
}
