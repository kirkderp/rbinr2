use std::collections::{BTreeMap, HashMap};

use rbm_core::{ToolError, ToolResult};
use regex::Regex;
use serde_json::{Value, json};

use crate::disasm::validate_addr;
use crate::session::Session;

const DEFAULT_MAX_INSTRUCTIONS: u32 = 800;
const MAX_INSTRUCTIONS: u32 = 5000;
const DEFAULT_MAX_ROWS: usize = 60;
const MAX_ROWS: usize = 2000;

#[derive(Debug, Clone)]
pub struct FieldXrefsOptions<'a> {
    pub arch: Option<&'a str>,
    pub bits: u32,
    pub range_end: Option<&'a str>,
    pub root_register: Option<&'a str>,
    pub root_name: Option<&'a str>,
    pub arg_names: Option<&'a str>,
    pub resolver_function: Option<&'a str>,
    pub marker_constants: Option<&'a str>,
    pub ignore_stack: bool,
    pub max_instructions: u32,
    pub max_rows: usize,
}

/// Scan instructions through r2 and summarize field-like memory references.
///
/// # Errors
///
/// Returns an error if addresses, r2 settings, root metadata, or marker options
/// are invalid, or if the r2 disassembly command fails.
pub async fn field_xrefs(
    session: &Session,
    start_addr: &str,
    options: FieldXrefsOptions<'_>,
) -> ToolResult<Value> {
    validate_addr(start_addr)?;
    if let Some(end) = options.range_end {
        validate_addr(end)?;
    }
    if let Some(arch) = options.arch {
        validate_r2_setting("arch", arch)?;
        session.cmd(format!("e asm.arch={arch}")).await?;
    }
    if options.bits != 0 {
        validate_bits(options.bits)?;
        session.cmd(format!("e asm.bits={}", options.bits)).await?;
    }
    if let Some(register) = options.root_register.filter(|s| !s.trim().is_empty()) {
        validate_token("root_register", register)?;
    }
    if let Some(name) = options.root_name.filter(|s| !s.trim().is_empty()) {
        validate_symbol_name("root_name", name)?;
    }
    if let Some(resolver) = options.resolver_function.filter(|s| !s.trim().is_empty()) {
        validate_addr(resolver)?;
    }

    let max_instructions = clamp_instructions(options.max_instructions);
    let ops = session
        .cmdj(format!("pdj {max_instructions} @ {start_addr}"))
        .await?;
    let ops = match ops {
        Value::Array(arr) => arr,
        _ => Vec::new(),
    };

    build_field_xrefs(start_addr, &ops, &options)
}

/// Build a field-xref summary from already-collected r2 instruction objects.
///
/// # Errors
///
/// Returns an error if argument-name or marker-constant option strings are
/// malformed.
pub fn build_field_xrefs(
    start_addr: &str,
    ops: &[Value],
    options: &FieldXrefsOptions<'_>,
) -> ToolResult<Value> {
    let config = FieldXrefsConfig::from_options(options)?;
    let collected = collect_field_xrefs(ops, &config);
    let field_summaries = summarize_fields(collected.fields);

    Ok(json!({
        "schema": "rbm.r2.field_xrefs.v0",
        "start_addr": start_addr,
        "range_end": options.range_end,
        "arch": options.arch,
        "bits": options.bits,
        "root_register": config.root_register,
        "root_name": config.root_name,
        "arg_names": options.arg_names,
        "resolver_function": options.resolver_function,
        "ignore_stack": options.ignore_stack,
        "instruction_count": collected.scanned,
        "field_ref_count": collected.field_refs.len(),
        "assignment_count": collected.assignments.len(),
        "truncated": collected.truncated,
        "field_summaries": field_summaries,
        "assignments": collected.assignments,
        "field_refs": collected.field_refs,
    }))
}

#[derive(Debug, Clone)]
struct MemRef {
    text: String,
    size: Option<String>,
    base: String,
    offset: i64,
}

#[derive(Debug, Default)]
struct FieldSummary {
    reads: usize,
    writes: usize,
    read_writes: usize,
    addresses: Vec<String>,
}

struct FieldXrefsConfig {
    range_end: Option<u64>,
    root_register: Option<String>,
    root_name: String,
    arg_names: BTreeMap<i64, String>,
    resolver_function: Option<String>,
    markers: BTreeMap<String, String>,
    ignore_stack: bool,
    max_rows: usize,
}

impl FieldXrefsConfig {
    fn from_options(options: &FieldXrefsOptions<'_>) -> ToolResult<Self> {
        Ok(Self {
            range_end: options.range_end.and_then(parse_addr_u64),
            root_register: options
                .root_register
                .filter(|s| !s.trim().is_empty())
                .map(str::to_ascii_lowercase),
            root_name: options.root_name.unwrap_or("root").to_string(),
            arg_names: parse_arg_names(options.arg_names.unwrap_or_default())?,
            resolver_function: options
                .resolver_function
                .and_then(parse_addr_u64)
                .map(|addr| format!("{addr:#x}")),
            markers: parse_marker_constants(options.marker_constants.unwrap_or_default())?,
            ignore_stack: options.ignore_stack,
            max_rows: clamp_rows(options.max_rows),
        })
    }
}

struct FieldXrefsCollected {
    fields: BTreeMap<String, FieldSummary>,
    field_refs: Vec<Value>,
    assignments: Vec<Value>,
    scanned: usize,
    truncated: bool,
}

struct FieldXrefOpContext<'a> {
    opcode: &'a str,
    lower: &'a str,
    operands: &'a [String],
    address: &'a str,
    disasm: &'a str,
}

fn collect_field_xrefs(ops: &[Value], config: &FieldXrefsConfig) -> FieldXrefsCollected {
    let mut regs = HashMap::new();
    if let Some(register) = &config.root_register {
        regs.insert(register.clone(), config.root_name.clone());
    }

    let mut collected = FieldXrefsCollected {
        fields: BTreeMap::new(),
        field_refs: Vec::new(),
        assignments: Vec::new(),
        scanned: 0,
        truncated: false,
    };
    let mut pending_push: Option<String> = None;

    for op in ops {
        let Some(addr) = op.get("addr").and_then(Value::as_u64) else {
            continue;
        };
        if config.range_end.is_some_and(|end| addr >= end) {
            break;
        }
        collect_field_xref_op(
            op,
            addr,
            config,
            &mut regs,
            &mut pending_push,
            &mut collected,
        );
    }

    collected
}

fn collect_field_xref_op(
    op: &Value,
    addr: u64,
    config: &FieldXrefsConfig,
    regs: &mut HashMap<String, String>,
    pending_push: &mut Option<String>,
    collected: &mut FieldXrefsCollected,
) {
    collected.scanned += 1;
    let opcode = text_field(op, "opcode");
    let disasm = nonempty(&text_field(op, "disasm"), &opcode).to_string();
    let address = format!("{addr:#x}");
    let lower = opcode.trim().to_ascii_lowercase();
    let operands = split_operands(&opcode);
    let op_context = FieldXrefOpContext {
        opcode: &opcode,
        lower: &lower,
        operands: &operands,
        address: &address,
        disasm: &disasm,
    };

    collect_memrefs(&op_context, config, regs, collected);
    collect_assignment(
        &lower, &operands, &address, &disasm, config, regs, collected,
    );
    update_push_resolver_state(&lower, &operands, config, regs, pending_push);
}

fn collect_memrefs(
    op_context: &FieldXrefOpContext<'_>,
    config: &FieldXrefsConfig,
    regs: &HashMap<String, String>,
    collected: &mut FieldXrefsCollected,
) {
    for memref in parse_memrefs(op_context.opcode)
        .iter()
        .filter(|m| keep_memref(m, config.ignore_stack))
    {
        let access = classify_access(op_context.lower, op_context.operands, memref);
        let object = object_for_memref(memref, regs, &config.arg_names);
        let field_key = format!("{}{}", object, format_offset(memref.offset));
        bump_field(
            &mut collected.fields,
            &field_key,
            &access,
            op_context.address,
        );
        push_limited(
            &mut collected.field_refs,
            &mut collected.truncated,
            config.max_rows,
            json!({
                "address": op_context.address,
                "access": access,
                "object": object,
                "base_register": memref.base,
                "offset": format_signed_hex(memref.offset),
                "size": memref.size,
                "disassembly": op_context.disasm,
            }),
        );
    }
}

fn collect_assignment(
    lower: &str,
    operands: &[String],
    address: &str,
    disasm: &str,
    config: &FieldXrefsConfig,
    regs: &HashMap<String, String>,
    collected: &mut FieldXrefsCollected,
) {
    if let Some(assignment) = parse_assignment(
        lower,
        operands,
        regs,
        &config.arg_names,
        address,
        disasm,
        config.ignore_stack,
    ) {
        push_limited(
            &mut collected.assignments,
            &mut collected.truncated,
            config.max_rows,
            assignment,
        );
    }
}

fn update_push_resolver_state(
    lower: &str,
    operands: &[String],
    config: &FieldXrefsConfig,
    regs: &mut HashMap<String, String>,
    pending_push: &mut Option<String>,
) {
    if lower.starts_with("push ") {
        *pending_push = parse_immediate_operand(operands.first().map_or("", String::as_str))
            .map(|value| marker_label(value, &config.markers));
    } else if lower.starts_with("call ") {
        if config
            .resolver_function
            .as_deref()
            .is_some_and(|resolver| call_targets(lower, resolver))
        {
            if let Some(value) = pending_push.take() {
                regs.insert("eax".to_string(), value.clone());
                regs.insert("rax".to_string(), value);
            }
        } else {
            *pending_push = None;
        }
    } else {
        update_register_aliases(lower, operands, regs, &config.arg_names);
    }
}

fn summarize_fields(fields: BTreeMap<String, FieldSummary>) -> Vec<Value> {
    fields
        .into_iter()
        .map(|(field, summary)| {
            json!({
                "field": field,
                "read_count": summary.reads,
                "write_count": summary.writes,
                "read_write_count": summary.read_writes,
                "addresses_preview": summary.addresses,
            })
        })
        .collect()
}

/// Parse stack argument names from `offset=name` entries.
///
/// # Errors
///
/// Returns an error if an entry is missing a separator, has a nonnumeric offset,
/// or contains an invalid symbol name.
pub fn parse_arg_names(input: &str) -> ToolResult<BTreeMap<i64, String>> {
    let mut names = BTreeMap::new();
    for raw in input.split([',', '\n']) {
        let item = raw.trim();
        if item.is_empty() {
            continue;
        }
        let (offset, name) = item
            .split_once('=')
            .or_else(|| item.split_once(':'))
            .ok_or_else(|| {
                ToolError::invalid(format!("arg_names entry must use offset=name: {item:?}"))
            })?;
        let offset = parse_signed_offset(offset).ok_or_else(|| {
            ToolError::invalid(format!("arg_names offset is not numeric: {offset:?}"))
        })?;
        let name = name.trim();
        validate_symbol_name("arg name", name)?;
        names.insert(offset, name.to_string());
    }
    Ok(names)
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

fn parse_assignment(
    lower: &str,
    operands: &[String],
    regs: &HashMap<String, String>,
    arg_names: &BTreeMap<i64, String>,
    address: &str,
    disasm: &str,
    ignore_stack: bool,
) -> Option<Value> {
    if !lower.starts_with("mov ") || operands.len() < 2 {
        return None;
    }
    let dst = parse_memrefs(&operands[0]).into_iter().next()?;
    if !keep_memref(&dst, ignore_stack) {
        return None;
    }
    let dst_object = object_for_memref(&dst, regs, arg_names);
    let src = symbolic_operand(&operands[1], regs, arg_names);
    Some(json!({
        "address": address,
        "destination": format!("{}{}", dst_object, format_offset(dst.offset)),
        "destination_object": dst_object,
        "destination_offset": format_signed_hex(dst.offset),
        "source": src,
        "disassembly": disasm,
    }))
}

fn update_register_aliases(
    lower: &str,
    operands: &[String],
    regs: &mut HashMap<String, String>,
    arg_names: &BTreeMap<i64, String>,
) {
    if operands.len() < 2 {
        return;
    }
    let Some(dst) = register_operand(&operands[0]) else {
        return;
    };
    if lower.starts_with("mov ") || lower.starts_with("lea ") {
        let src = symbolic_operand(&operands[1], regs, arg_names);
        if src.is_empty() {
            regs.remove(&dst);
        } else {
            regs.insert(dst, src);
        }
    } else if lower.starts_with("xor ") && register_operand(&operands[1]).as_deref() == Some(&dst) {
        regs.insert(dst, "0".to_string());
    } else if (lower.starts_with("add ") || lower.starts_with("sub "))
        && parse_immediate_operand(&operands[1]).is_some()
    {
        let sign = if lower.starts_with("sub ") { "-" } else { "+" };
        let imm = parse_immediate_operand(&operands[1]).unwrap_or_default();
        let current = regs.remove(&dst).unwrap_or_else(|| dst.clone());
        regs.insert(dst, format!("{current}{sign}{imm}"));
    }
}

fn symbolic_operand(
    operand: &str,
    regs: &HashMap<String, String>,
    arg_names: &BTreeMap<i64, String>,
) -> String {
    if let Some(register) = register_operand(operand) {
        return regs.get(&register).cloned().unwrap_or(register);
    }
    if let Some(memref) = parse_memrefs(operand).into_iter().next() {
        if is_stack_register(&memref.base) && arg_names.contains_key(&memref.offset) {
            return object_for_memref(&memref, regs, arg_names);
        }
        return object_for_memref(&memref, regs, arg_names) + &format_offset(memref.offset);
    }
    if let Some(value) = parse_immediate_operand(operand) {
        return value;
    }
    operand.trim().to_string()
}

fn object_for_memref(
    memref: &MemRef,
    regs: &HashMap<String, String>,
    arg_names: &BTreeMap<i64, String>,
) -> String {
    if is_stack_register(&memref.base)
        && let Some(name) = arg_names.get(&memref.offset)
    {
        return name.clone();
    }
    regs.get(&memref.base)
        .cloned()
        .unwrap_or_else(|| memref.base.clone())
}

fn parse_memrefs(opcode: &str) -> Vec<MemRef> {
    let re = Regex::new(
        r"(?i)(?:(byte|word|dword|qword|oword)\s+)?(\[[a-z][a-z0-9]*(?:\s*[+-]\s*(?:0x[0-9a-f]+|\d+))?\])",
    )
    .expect("memory reference regex");
    let inner_re = Regex::new(r"(?i)^\[([a-z][a-z0-9]*)(?:\s*([+-])\s*(0x[0-9a-f]+|\d+))?\]$")
        .expect("memory inner regex");
    re.captures_iter(opcode)
        .filter_map(|caps| {
            let text = caps.get(2)?.as_str().to_string();
            let inner = inner_re.captures(&text)?;
            let base = inner.get(1)?.as_str().to_ascii_lowercase();
            let mut offset = inner
                .get(3)
                .and_then(|m| parse_addr_u64(m.as_str()))
                .and_then(|value| i64::try_from(value).ok())
                .unwrap_or(0);
            if inner.get(2).is_some_and(|m| m.as_str() == "-") {
                offset = -offset;
            }
            Some(MemRef {
                text,
                size: caps.get(1).map(|m| m.as_str().to_ascii_lowercase()),
                base,
                offset,
            })
        })
        .collect()
}

fn split_operands(opcode: &str) -> Vec<String> {
    let Some((_, rest)) = opcode.trim().split_once(char::is_whitespace) else {
        return Vec::new();
    };
    rest.split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

fn classify_access(lower: &str, operands: &[String], memref: &MemRef) -> String {
    let is_first = operands
        .first()
        .is_some_and(|operand| operand.contains(&memref.text.to_ascii_lowercase()));
    if is_first {
        if lower.starts_with("cmp ") || lower.starts_with("test ") {
            "read".to_string()
        } else if lower.starts_with("mov ") || lower.starts_with("lea ") {
            "write".to_string()
        } else {
            "read_write".to_string()
        }
    } else {
        "read".to_string()
    }
}

fn keep_memref(memref: &MemRef, ignore_stack: bool) -> bool {
    !(ignore_stack && is_stack_register(&memref.base))
}

fn is_stack_register(register: &str) -> bool {
    matches!(register, "esp" | "ebp" | "rsp" | "rbp" | "sp" | "bp")
}

fn register_operand(operand: &str) -> Option<String> {
    let cleaned = operand.trim().to_ascii_lowercase();
    if cleaned
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
        && cleaned.chars().any(|c| c.is_ascii_alphabetic())
    {
        Some(cleaned)
    } else {
        None
    }
}

fn parse_immediate_operand(operand: &str) -> Option<String> {
    let value = operand.trim().trim_start_matches("0x");
    if operand.trim().starts_with("0x") {
        u64::from_str_radix(value, 16)
            .ok()
            .map(|parsed| format!("{parsed:#x}"))
    } else {
        operand
            .trim()
            .parse::<u64>()
            .ok()
            .map(|parsed| format!("{parsed:#x}"))
    }
}

fn marker_label(value: String, markers: &BTreeMap<String, String>) -> String {
    markers
        .get(&value)
        .map(|name| format!("{name}({value})"))
        .unwrap_or(value)
}

fn call_targets(lower: &str, target: &str) -> bool {
    lower.split_whitespace().nth(1).is_some_and(|call_target| {
        parse_addr_u64(call_target).is_some_and(|addr| format!("{addr:#x}") == target)
    })
}

fn bump_field(fields: &mut BTreeMap<String, FieldSummary>, key: &str, access: &str, address: &str) {
    let field = fields.entry(key.to_string()).or_default();
    match access {
        "write" => field.writes += 1,
        "read_write" => field.read_writes += 1,
        _ => field.reads += 1,
    }
    if field.addresses.len() < 16 {
        field.addresses.push(address.to_string());
    }
}

fn push_limited(out: &mut Vec<Value>, truncated: &mut bool, max_rows: usize, value: Value) {
    if out.len() >= max_rows {
        *truncated = true;
    } else {
        out.push(value);
    }
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
        8 | 16 | 32 | 64 => Ok(()),
        other => Err(ToolError::invalid(format!(
            "bits must be 8, 16, 32, or 64, got {other}"
        ))),
    }
}

fn validate_token(label: &str, value: &str) -> ToolResult<()> {
    if value.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        Ok(())
    } else {
        Err(ToolError::invalid(format!(
            "{label} must be register-like, got {value:?}"
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

fn clamp_rows(value: usize) -> usize {
    if value == 0 {
        DEFAULT_MAX_ROWS
    } else {
        value.min(MAX_ROWS)
    }
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

fn parse_signed_offset(value: &str) -> Option<i64> {
    let raw = value.trim();
    raw.strip_prefix('-').map_or_else(
        || parse_addr_u64(raw).and_then(|value| i64::try_from(value).ok()),
        |rest| {
            parse_addr_u64(rest)
                .and_then(|value| i64::try_from(value).ok())
                .map(std::ops::Neg::neg)
        },
    )
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

fn format_offset(value: i64) -> String {
    match value.cmp(&0) {
        std::cmp::Ordering::Equal => String::new(),
        std::cmp::Ordering::Less => format!("-{:#x}", value.unsigned_abs()),
        std::cmp::Ordering::Greater => format!("+{value:#x}"),
    }
}

fn format_signed_hex(value: i64) -> String {
    if value < 0 {
        format!("-{:#x}", value.unsigned_abs())
    } else {
        format!("{value:#x}")
    }
}
