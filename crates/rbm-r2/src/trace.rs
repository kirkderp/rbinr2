use std::collections::{BTreeMap, HashSet, VecDeque};

use rbm_core::{ToolError, ToolResult};
use regex::Regex;
use serde_json::{Value, json};

use crate::disasm::{first_function, validate_addr};
use crate::session::Session;

pub const MAX_NODES: usize = 200;
pub const MAX_EDGES: usize = 500;
pub const MIN_DEPTH: i64 = 1;
pub const MAX_DEPTH: i64 = 15;
const DEFAULT_VALUE_TRACE_INSTRUCTIONS: u32 = 300;
const MAX_VALUE_TRACE_INSTRUCTIONS: u32 = 5000;
const DEFAULT_VALUE_TRACE_EVENTS: usize = 100;
const MAX_VALUE_TRACE_EVENTS: usize = 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceDirection {
    Forward,
    Backward,
}

impl TraceDirection {
    /// Parse a data-flow trace direction.
    ///
    /// # Errors
    ///
    /// Returns an error if `direction` is not `forward`, `backward`, or empty.
    pub fn parse(direction: &str) -> ToolResult<Self> {
        match direction {
            "forward" => Ok(Self::Forward),
            "backward" | "" => Ok(Self::Backward),
            other => Err(ToolError::invalid(format!(
                "direction must be 'forward' or 'backward', got {other:?}"
            ))),
        }
    }

    #[must_use]
    pub fn xref_cmd(self, addr: &str) -> String {
        match self {
            Self::Forward => format!("axfj @ {addr}"),
            Self::Backward => format!("axtj @ {addr}"),
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Forward => "forward",
            Self::Backward => "backward",
        }
    }
}

#[must_use]
pub fn clamp_depth(requested: i64) -> i64 {
    requested.clamp(MIN_DEPTH, MAX_DEPTH)
}

#[must_use]
pub fn extract_target_hex(xref: &Value, direction: TraceDirection) -> Option<String> {
    let primary = match direction {
        TraceDirection::Backward => "from",
        TraceDirection::Forward => "to",
    };
    let raw = xref
        .get(primary)
        .or_else(|| xref.get("addr"))
        .or_else(|| xref.get("ref"))?;
    if let Some(n) = raw.as_u64() {
        return Some(format!("{n:#x}"));
    }
    if let Some(s) = raw.as_str() {
        return Some(s.to_string());
    }
    None
}

#[must_use]
pub fn build_edge(
    current: &str,
    target: &str,
    xref_type: &str,
    direction: TraceDirection,
) -> Value {
    match direction {
        TraceDirection::Forward => json!({
            "from": current,
            "to": target,
            "type": xref_type,
        }),
        TraceDirection::Backward => json!({
            "from": target,
            "to": current,
            "type": xref_type,
        }),
    }
}

#[must_use]
pub fn build_node(addr: &str, func_name: Option<&str>, depth: i64) -> Value {
    json!({
        "addr": addr,
        "func": func_name,
        "depth": depth,
    })
}

/// Trace xref-linked data-flow neighbourhoods from an address.
///
/// # Errors
///
/// Returns an error if the address is invalid, if an r2 command fails, or if
/// required r2 JSON output cannot be decoded.
pub async fn trace_data_flow(
    session: &Session,
    addr: &str,
    direction: TraceDirection,
    max_depth: i64,
) -> ToolResult<Value> {
    validate_addr(addr)?;
    let max_depth = clamp_depth(max_depth);

    let mut visited: HashSet<String> = HashSet::new();
    let mut nodes: Vec<Value> = Vec::new();
    let mut edges: Vec<Value> = Vec::new();
    let mut depth_reached: i64 = 0;

    let mut queue: VecDeque<(String, i64)> = VecDeque::new();
    let start = addr.to_string();
    queue.push_back((start.clone(), 0));
    visited.insert(start);

    while let Some((current_addr, depth)) = queue.pop_front() {
        if nodes.len() >= MAX_NODES {
            break;
        }
        if depth > max_depth {
            continue;
        }
        if depth > depth_reached {
            depth_reached = depth;
        }

        let func_info = session.cmdj(format!("afij @ {current_addr}")).await?;
        let func_name = first_function(func_info)
            .as_ref()
            .and_then(|f| f.get("name").and_then(Value::as_str).map(str::to_string));
        nodes.push(build_node(&current_addr, func_name.as_deref(), depth));

        if depth >= max_depth {
            continue;
        }

        let xrefs = session.cmdj(direction.xref_cmd(&current_addr)).await?;
        let Some(xref_arr) = xrefs.as_array() else {
            continue;
        };

        for xref in xref_arr {
            if edges.len() >= MAX_EDGES {
                break;
            }
            let Some(target) = extract_target_hex(xref, direction) else {
                continue;
            };
            let xref_type = xref
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            edges.push(build_edge(&current_addr, &target, xref_type, direction));

            if !visited.contains(&target) && nodes.len() + queue.len() < MAX_NODES {
                visited.insert(target.clone());
                queue.push_back((target, depth + 1));
            }
        }
    }

    Ok(json!({
        "start": addr,
        "direction": direction.as_str(),
        "depth_reached": depth_reached,
        "node_count": nodes.len(),
        "edge_count": edges.len(),
        "nodes": nodes,
        "edges": edges,
    }))
}

#[derive(Debug, Clone)]
pub struct ValueTraceOptions<'a> {
    pub arch: Option<&'a str>,
    pub bits: u32,
    pub seed_register: &'a str,
    pub seed_memory: Option<&'a str>,
    pub seed_value: Option<&'a str>,
    pub max_instructions: u32,
    pub max_events: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TrackedValue {
    expr: String,
    tainted: bool,
}

impl TrackedValue {
    const fn seed(expr: String) -> Self {
        Self {
            expr,
            tainted: true,
        }
    }

    const fn derived(expr: String, tainted: bool) -> Self {
        Self { expr, tainted }
    }
}

#[derive(Debug)]
struct ValueTraceState {
    regs: BTreeMap<String, TrackedValue>,
    memory: BTreeMap<String, TrackedValue>,
    stack: BTreeMap<i64, TrackedValue>,
    sp_delta: i64,
    word_size: i64,
    events: Vec<Value>,
    event_truncated: bool,
    max_events: usize,
    first_control_transfer: Option<Value>,
    last_tainted_event: Option<Value>,
    tainted_registers_seen: HashSet<String>,
}

impl ValueTraceState {
    fn new(
        seed_register: Option<String>,
        seed_memory: Option<String>,
        seed_expr: String,
        max_events: usize,
        word_size: i64,
    ) -> Self {
        let mut regs = BTreeMap::new();
        let mut memory = BTreeMap::new();
        let mut stack = BTreeMap::new();
        let mut tainted_registers_seen = HashSet::new();
        let seed = TrackedValue::seed(seed_expr);
        if let Some(seed_register) = seed_register {
            regs.insert(seed_register.clone(), seed.clone());
            tainted_registers_seen.insert(seed_register);
        }
        if let Some(seed_memory) = seed_memory {
            if let Some(offset) = parse_stack_seed_slot(&seed_memory) {
                stack.insert(offset, seed);
            } else {
                memory.insert(seed_memory, seed);
            }
        }
        Self {
            regs,
            memory,
            stack,
            sp_delta: 0,
            word_size,
            events: Vec::new(),
            event_truncated: false,
            max_events,
            first_control_transfer: None,
            last_tainted_event: None,
            tainted_registers_seen,
        }
    }

    fn push_event(&mut self, event: Value) {
        self.last_tainted_event = Some(event.clone());
        if self.events.len() < self.max_events {
            self.events.push(event);
        } else {
            self.event_truncated = true;
        }
    }

    fn push_control_transfer(&mut self, event: Value) {
        if self.first_control_transfer.is_none() {
            self.first_control_transfer = Some(event.clone());
        }
        self.push_event(event);
    }

    fn clear_registers(&mut self, registers: &[&str]) {
        for register in registers {
            self.regs.remove(*register);
        }
    }

    fn adjust_stack_pointer(&mut self, mnemonic: &str, amount: i64) {
        match mnemonic {
            "sub" => self.sp_delta -= amount,
            "add" => {
                let old = self.sp_delta;
                let new = self.sp_delta + amount;
                self.stack.retain(|slot, _| !(*slot >= old && *slot < new));
                self.sp_delta = new;
            }
            _ => {}
        }
    }

    fn push_stack(&mut self, value: TrackedValue) -> String {
        self.sp_delta -= self.word_size;
        self.stack.insert(self.sp_delta, value);
        format_stack_slot(self.sp_delta)
    }

    fn pop_stack(&mut self) -> Option<(String, TrackedValue)> {
        let slot = self.sp_delta;
        let value = self.stack.remove(&slot);
        self.sp_delta += self.word_size;
        value.map(|value| (format_stack_slot(slot), value))
    }
}

/// Trace how a seed value propagates through a decoded instruction window.
///
/// # Errors
///
/// Returns an error if the start address, seed, r2 setting, or bit width is
/// invalid, or if the r2 disassembly command fails.
pub async fn trace_seed_value(
    session: &Session,
    start_addr: &str,
    options: ValueTraceOptions<'_>,
) -> ToolResult<Value> {
    validate_addr(start_addr)?;
    let seed_register = normalize_optional_register(options.seed_register)?;
    let seed_memory = normalize_optional_memory(options.seed_memory)?;
    if seed_register.is_none() && seed_memory.is_none() {
        return Err(ToolError::invalid(
            "seed_register or seed_memory must be provided",
        ));
    }
    if let Some(seed_value) = options.seed_value {
        validate_optional_value(seed_value)?;
    }
    if let Some(arch) = options.arch {
        validate_r2_setting("arch", arch)?;
    }
    validate_bits(options.bits)?;

    let max_instructions = clamp_value_trace_instructions(options.max_instructions);
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

    build_seed_value_trace(start_addr, &ops, &options)
}

/// Build a seed-value trace from already-collected r2 instruction objects.
///
/// # Errors
///
/// Returns an error if seed register, seed memory, seed value, or bit width
/// options are invalid.
pub fn build_seed_value_trace(
    start_addr: &str,
    ops: &[Value],
    options: &ValueTraceOptions<'_>,
) -> ToolResult<Value> {
    let config = SeedTraceConfig::from_options(options)?;
    let mut state = ValueTraceState::new(
        config.seed_register.clone(),
        config.seed_memory.clone(),
        config.seed_expr.clone(),
        config.max_events,
        config.word_size,
    );
    let scanned = run_seed_trace(ops, &mut state);

    let mut tainted_registers_seen: Vec<_> = state.tainted_registers_seen.into_iter().collect();
    tainted_registers_seen.sort();

    Ok(json!({
        "schema": "rbm.r2.value_trace.v0",
        "start_addr": start_addr,
        "seed_register": config.seed_register.unwrap_or_default(),
        "seed_memory": config.seed_memory.unwrap_or_default(),
        "seed_value": options.seed_value.unwrap_or(""),
        "instruction_count": scanned,
        "event_count": state.events.len(),
        "event_truncated": state.event_truncated,
        "events": state.events,
        "tainted_registers": tainted_register_snapshot(&state.regs),
        "tainted_memory": tainted_memory_snapshot(&state.memory, &state.stack),
        "stack_pointer_delta": format_signed_hex(state.sp_delta),
        "tainted_registers_seen": tainted_registers_seen,
        "first_control_transfer": state.first_control_transfer,
        "last_tainted_event": state.last_tainted_event,
    }))
}

struct SeedTraceConfig {
    seed_register: Option<String>,
    seed_memory: Option<String>,
    seed_expr: String,
    max_events: usize,
    word_size: i64,
}

impl SeedTraceConfig {
    fn from_options(options: &ValueTraceOptions<'_>) -> ToolResult<Self> {
        let seed_register = normalize_optional_register(options.seed_register)?;
        let seed_memory = normalize_optional_memory(options.seed_memory)?;
        if seed_register.is_none() && seed_memory.is_none() {
            return Err(ToolError::invalid(
                "seed_register or seed_memory must be provided",
            ));
        }
        let seed_expr = seed_expr(
            options.seed_value,
            seed_register.as_ref(),
            seed_memory.as_ref(),
        );
        Ok(Self {
            seed_register,
            seed_memory,
            seed_expr,
            max_events: clamp_value_trace_events(options.max_events),
            word_size: word_size_for_bits(options.bits),
        })
    }
}

fn seed_expr(
    seed_value: Option<&str>,
    seed_register: Option<&String>,
    seed_memory: Option<&String>,
) -> String {
    seed_value.filter(|s| !s.trim().is_empty()).map_or_else(
        || seed_register.or(seed_memory).cloned().unwrap_or_default(),
        |value| match (seed_register, seed_memory) {
            (Some(register), _) => format!("{register}={value}"),
            (None, Some(memory)) => format!("{memory}={value}"),
            (None, None) => value.to_string(),
        },
    )
}

fn run_seed_trace(ops: &[Value], state: &mut ValueTraceState) -> usize {
    let mut scanned = 0usize;
    for op in ops {
        let Some(addr) = op.get("addr").and_then(Value::as_u64) else {
            continue;
        };
        scanned += 1;
        if process_seed_trace_op(op, addr, state) {
            break;
        }
    }
    scanned
}

fn process_seed_trace_op(op: &Value, addr: u64, state: &mut ValueTraceState) -> bool {
    let opcode = text_field(op, "opcode");
    let disasm = nonempty(&text_field(op, "disasm"), &opcode).to_string();
    let kind = text_field(op, "type");
    let address = format!("{addr:#x}");

    if let Some((mnemonic, operands)) = split_opcode(&opcode)
        && handle_seed_mnemonic(state, &address, &disasm, &mnemonic, &operands)
    {
        return true;
    }
    handle_seed_kind_without_mnemonic(state, &kind, &opcode, &address, &disasm)
}

fn handle_seed_mnemonic(
    state: &mut ValueTraceState,
    address: &str,
    disasm: &str,
    mnemonic: &str,
    operands: &[String],
) -> bool {
    match mnemonic {
        "mov" | "movzx" | "movsxd" if operands.len() >= 2 => {
            handle_assignment(state, address, disasm, &operands[0], &operands[1]);
        }
        "lea" if operands.len() >= 2 => {
            handle_assignment(
                state,
                address,
                disasm,
                &operands[0],
                &format!("addr({})", operands[1]),
            );
        }
        "push" => handle_seed_push(state, address, disasm, operands),
        "pop" => handle_seed_pop(state, address, disasm, operands),
        "add" | "sub" | "xor" | "or" | "and" | "shl" | "shr" | "sar" | "rol" | "ror"
            if operands.len() >= 2 =>
        {
            handle_seed_mutation(state, address, disasm, mnemonic, operands);
        }
        "inc" | "dec" | "not" | "neg" => {
            if let Some(dst) = operands.first() {
                mutate_destination(state, address, disasm, mnemonic, dst, "");
            }
        }
        "call" | "jmp" => {
            return handle_seed_control_transfer(state, address, disasm, mnemonic, operands);
        }
        "ret" | "retf" | "iret" | "iretd" | "iretq" => return true,
        _ => {}
    }
    false
}

fn handle_seed_push(state: &mut ValueTraceState, address: &str, disasm: &str, operands: &[String]) {
    if let Some(src) = operands.first()
        && let Some(value) = resolve_operand(src, state)
        && value.tainted
    {
        let slot = state.push_stack(value.clone());
        state.push_event(json!({
            "address": address,
            "kind": "seed_push",
            "disassembly": disasm,
            "source": src,
            "stack_slot": slot,
            "value": value.expr,
        }));
    }
}

fn handle_seed_pop(state: &mut ValueTraceState, address: &str, disasm: &str, operands: &[String]) {
    if let Some(dst) = operands.first()
        && let Some((slot, value)) = state.pop_stack()
        && value.tainted
    {
        write_destination(state, dst, value);
        state.push_event(json!({
            "address": address,
            "kind": "seed_pop",
            "disassembly": disasm,
            "destination": dst,
            "stack_slot": slot,
        }));
    }
}

fn handle_seed_mutation(
    state: &mut ValueTraceState,
    address: &str,
    disasm: &str,
    mnemonic: &str,
    operands: &[String],
) {
    if is_stack_pointer(&operands[0])
        && let Some(amount) = parse_immediate(&operands[1])
        && (mnemonic == "add" || mnemonic == "sub")
    {
        state.adjust_stack_pointer(mnemonic, amount);
        return;
    }
    mutate_destination(state, address, disasm, mnemonic, &operands[0], &operands[1]);
}

fn handle_seed_control_transfer(
    state: &mut ValueTraceState,
    address: &str,
    disasm: &str,
    mnemonic: &str,
    operands: &[String],
) -> bool {
    let target = operands.first().cloned().unwrap_or_default();
    let operand_value = resolve_operand(&target, state);
    let operand_tainted = operand_value.as_ref().is_some_and(|v| v.tainted)
        || operand_mentions_tainted(&target, &state.regs);
    let setup = tainted_register_snapshot(&state.regs);
    if operand_tainted || !setup.is_empty() {
        state.push_control_transfer(json!({
            "address": address,
            "kind": if mnemonic == "call" { "seed_reaches_call" } else { "seed_reaches_jump" },
            "disassembly": disasm,
            "target": target,
            "target_value": operand_value.map(|v| v.expr),
            "tainted_registers": setup,
        }));
    }
    if mnemonic == "call" {
        state.clear_registers(&["eax", "ecx", "edx", "rax", "rcx", "rdx"]);
        false
    } else {
        true
    }
}

fn handle_seed_kind_without_mnemonic(
    state: &mut ValueTraceState,
    kind: &str,
    opcode: &str,
    address: &str,
    disasm: &str,
) -> bool {
    if (kind == "call" || kind == "ucall" || kind == "icall")
        && split_opcode(opcode).is_none_or(|(m, _)| m != "call")
    {
        let setup = tainted_register_snapshot(&state.regs);
        if !setup.is_empty() {
            state.push_control_transfer(json!({
                "address": address,
                "kind": "seed_reaches_call",
                "disassembly": disasm,
                "tainted_registers": setup,
            }));
        }
        state.clear_registers(&["eax", "ecx", "edx", "rax", "rcx", "rdx"]);
    }
    kind == "ujmp" || kind == "ijmp" || kind == "ret"
}

fn handle_assignment(
    state: &mut ValueTraceState,
    address: &str,
    disasm: &str,
    dst: &str,
    src: &str,
) {
    let source = resolve_operand(src, state).unwrap_or_else(|| {
        TrackedValue::derived(
            src.trim().to_string(),
            operand_mentions_tainted(src, &state.regs),
        )
    });
    let tainted = source.tainted;
    write_destination(state, dst, source.clone());
    if tainted {
        let event = json!({
            "address": address,
            "kind": if is_memory_operand(dst) { "seed_memory_write" } else { "seed_assign" },
            "disassembly": disasm,
            "destination": dst,
            "source": src,
            "value": source.expr,
        });
        state.push_event(event);
    }
}

fn mutate_destination(
    state: &mut ValueTraceState,
    address: &str,
    disasm: &str,
    mnemonic: &str,
    dst: &str,
    src: &str,
) {
    let Some(reg) = normalize_register(dst).ok() else {
        return;
    };
    let old = state.regs.get(&reg).cloned();
    let src_value = resolve_operand(src, state);
    let tainted = old.as_ref().is_some_and(|v| v.tainted)
        || src_value.as_ref().is_some_and(|v| v.tainted)
        || operand_mentions_tainted(src, &state.regs);
    if !tainted {
        return;
    }
    let old_expr = old.map_or_else(|| reg.clone(), |v| v.expr);
    let expr = if src.trim().is_empty() {
        format!("{mnemonic}({old_expr})")
    } else {
        format!("{mnemonic}({old_expr}, {})", src.trim())
    };
    state
        .regs
        .insert(reg.clone(), TrackedValue::derived(expr.clone(), true));
    state.tainted_registers_seen.insert(reg.clone());
    let event = json!({
        "address": address,
        "kind": "seed_mutation",
        "disassembly": disasm,
        "destination": reg,
        "value": expr,
    });
    state.push_event(event);
}

fn write_destination(state: &mut ValueTraceState, dst: &str, value: TrackedValue) {
    if let Ok(reg) = normalize_register(dst) {
        if value.tainted {
            state.tainted_registers_seen.insert(reg.clone());
            state.regs.insert(reg, value);
        } else {
            state.regs.remove(&reg);
        }
    } else if is_memory_operand(dst) {
        let key = normalize_memory_operand(dst);
        if let Some(stack_slot) = stack_operand_offset(&key, state.sp_delta) {
            if value.tainted {
                state.stack.insert(stack_slot, value);
            } else {
                state.stack.remove(&stack_slot);
            }
        } else if value.tainted {
            state.memory.insert(key, value);
        } else {
            state.memory.remove(&key);
        }
    }
}

fn resolve_operand(operand: &str, state: &ValueTraceState) -> Option<TrackedValue> {
    if let Ok(reg) = normalize_register(operand) {
        return state.regs.get(&reg).cloned();
    }
    if is_memory_operand(operand) {
        let key = normalize_memory_operand(operand);
        if let Some(stack_slot) = stack_operand_offset(&key, state.sp_delta) {
            return state.stack.get(&stack_slot).cloned().or_else(|| {
                if operand_mentions_tainted(operand, &state.regs) {
                    Some(TrackedValue::derived(
                        format!("mem[{}]", format_stack_slot(stack_slot)),
                        true,
                    ))
                } else {
                    None
                }
            });
        }
        return state.memory.get(&key).cloned().or_else(|| {
            if operand_mentions_tainted(operand, &state.regs) {
                Some(TrackedValue::derived(format!("mem[{key}]"), true))
            } else {
                None
            }
        });
    }
    None
}

fn operand_mentions_tainted(
    operand: &str,
    regs: &std::collections::BTreeMap<String, TrackedValue>,
) -> bool {
    let lower = operand.to_ascii_lowercase();
    regs.iter()
        .any(|(reg, value)| value.tainted && lower.contains(reg))
}

fn tainted_register_snapshot(
    regs: &std::collections::BTreeMap<String, TrackedValue>,
) -> Vec<Value> {
    regs.iter()
        .filter(|(_, value)| value.tainted)
        .map(|(reg, value)| {
            json!({
                "register": reg,
                "value": value.expr,
            })
        })
        .collect()
}

fn tainted_memory_snapshot(
    memory: &BTreeMap<String, TrackedValue>,
    stack: &BTreeMap<i64, TrackedValue>,
) -> Vec<Value> {
    let mut rows: Vec<_> = memory
        .iter()
        .filter(|(_, value)| value.tainted)
        .map(|(slot, value)| {
            json!({
                "slot": slot,
                "value": value.expr,
            })
        })
        .collect();
    rows.extend(
        stack
            .iter()
            .filter(|(_, value)| value.tainted)
            .map(|(slot, value)| {
                json!({
                    "slot": format_stack_slot(*slot),
                    "value": value.expr,
                })
            }),
    );
    rows
}

fn split_opcode(opcode: &str) -> Option<(String, Vec<String>)> {
    let trimmed = opcode.trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut parts = trimmed.splitn(2, char::is_whitespace);
    let mnemonic = parts.next()?.to_ascii_lowercase();
    let operands = parts
        .next()
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    Some((mnemonic, operands))
}

fn normalize_register(raw: &str) -> ToolResult<String> {
    let reg = raw.trim().trim_start_matches('%').to_ascii_lowercase();
    let re = Regex::new(r"^[a-z][a-z0-9]{1,4}$").expect("valid register regex");
    if re.is_match(&reg) && !reg.contains('[') && !reg.contains('+') && !reg.contains('-') {
        Ok(reg)
    } else {
        Err(ToolError::invalid(format!("invalid register name {raw:?}")))
    }
}

fn normalize_optional_register(raw: &str) -> ToolResult<Option<String>> {
    if raw.trim().is_empty() {
        Ok(None)
    } else {
        normalize_register(raw).map(Some)
    }
}

fn normalize_optional_memory(raw: Option<&str>) -> ToolResult<Option<String>> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    let memory = normalize_memory_operand(raw);
    if is_memory_operand(&memory) || parse_stack_seed_slot(&memory).is_some() {
        Ok(Some(memory))
    } else {
        Err(ToolError::invalid(format!("invalid memory seed {raw:?}")))
    }
}

fn is_memory_operand(operand: &str) -> bool {
    operand.contains('[') && operand.contains(']')
}

fn normalize_memory_operand(operand: &str) -> String {
    operand
        .trim()
        .to_ascii_lowercase()
        .replace("dword ptr ", "")
        .replace("qword ptr ", "")
        .replace("word ptr ", "")
        .replace("byte ptr ", "")
        .replace("dword ", "")
        .replace("qword ", "")
        .replace("word ", "")
        .replace("byte ", "")
        .replace(' ', "")
}

const fn word_size_for_bits(bits: u32) -> i64 {
    if bits == 64 { 8 } else { 4 }
}

fn is_stack_pointer(operand: &str) -> bool {
    normalize_register(operand).is_ok_and(|reg| matches!(reg.as_str(), "esp" | "rsp" | "sp"))
}

fn parse_stack_seed_slot(seed: &str) -> Option<i64> {
    let stack =
        Regex::new(r"^stack\[([+-]?0x[0-9a-f]+|[+-]?\d+)\]$").expect("valid stack slot regex");
    let captures = stack.captures(seed)?;
    parse_signed_number(captures.get(1)?.as_str())
}

fn stack_operand_offset(memory: &str, sp_delta: i64) -> Option<i64> {
    let inner = memory.strip_prefix('[')?.strip_suffix(']')?;
    let rest = inner
        .strip_prefix("esp")
        .or_else(|| inner.strip_prefix("rsp"))
        .or_else(|| inner.strip_prefix("sp"))?;
    if rest.is_empty() {
        return Some(sp_delta);
    }
    parse_signed_number(rest).map(|offset| sp_delta + offset)
}

fn parse_immediate(raw: &str) -> Option<i64> {
    parse_signed_number(raw.trim())
}

fn parse_signed_number(raw: &str) -> Option<i64> {
    let raw = raw.trim().replace('_', "");
    let (sign, body) = match raw.as_bytes().first().copied() {
        Some(b'-') => (-1, &raw[1..]),
        Some(b'+') => (1, &raw[1..]),
        _ => (1, raw.as_str()),
    };
    let value = if let Some(hex) = body.strip_prefix("0x") {
        i64::from_str_radix(hex, 16).ok()?
    } else {
        body.parse::<i64>().ok()?
    };
    Some(sign * value)
}

fn format_stack_slot(offset: i64) -> String {
    format!("stack[{}]", format_signed_hex(offset))
}

fn format_signed_hex(value: i64) -> String {
    if value < 0 {
        format!("-0x{:x}", value.unsigned_abs())
    } else {
        format!("+0x{value:x}")
    }
}

fn text_field(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn nonempty<'a>(primary: &'a str, alternate: &'a str) -> &'a str {
    if primary.trim().is_empty() {
        alternate
    } else {
        primary
    }
}

fn clamp_value_trace_instructions(requested: u32) -> u32 {
    if requested == 0 {
        DEFAULT_VALUE_TRACE_INSTRUCTIONS
    } else {
        requested.min(MAX_VALUE_TRACE_INSTRUCTIONS)
    }
}

fn clamp_value_trace_events(requested: usize) -> usize {
    if requested == 0 {
        DEFAULT_VALUE_TRACE_EVENTS
    } else {
        requested.min(MAX_VALUE_TRACE_EVENTS)
    }
}

fn validate_r2_setting(name: &str, value: &str) -> ToolResult<()> {
    if value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    {
        Ok(())
    } else {
        Err(ToolError::invalid(format!(
            "{name} contains unsupported characters: {value:?}"
        )))
    }
}

fn validate_bits(bits: u32) -> ToolResult<()> {
    match bits {
        0 | 8 | 16 | 32 | 64 => Ok(()),
        other => Err(ToolError::invalid(format!(
            "bits must be one of 0, 8, 16, 32, 64; got {other}"
        ))),
    }
}

fn validate_optional_value(value: &str) -> ToolResult<()> {
    if value
        .chars()
        .all(|c| c.is_ascii_hexdigit() || matches!(c, 'x' | 'X' | '_' | '-' | '+'))
    {
        Ok(())
    } else {
        Err(ToolError::invalid(format!(
            "seed_value contains unsupported characters: {value:?}"
        )))
    }
}
