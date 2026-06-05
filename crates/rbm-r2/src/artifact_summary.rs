use std::collections::{BTreeMap, VecDeque};
use std::sync::OnceLock;

use rbm_core::{ToolError, ToolResult};
use regex::Regex;
use serde_json::{Value, json};

use crate::disasm::{validate_addr, validate_value};
use crate::session::Session;

const DEFAULT_MAX_INSTRUCTIONS: u32 = 1200;
const MAX_INSTRUCTIONS: u32 = 5000;
const DEFAULT_MAX_STEPS: usize = 20000;
const MAX_STEPS: usize = 100_000;
const DEFAULT_MIN_STRING: usize = 4;

#[derive(Debug, Clone)]
pub struct ArtifactSummaryOptions<'a> {
    pub arch: Option<&'a str>,
    pub bits: u32,
    pub range_end: Option<&'a str>,
    pub max_instructions: u32,
    pub max_steps: usize,
    pub min_string_len: usize,
}

/// Scan instructions through r2 and summarize simple decoded artifacts.
///
/// # Errors
///
/// Returns an error if addresses, r2 settings, or bit width options are invalid,
/// or if the r2 session command fails.
pub async fn artifact_summary(
    session: &Session,
    start_addr: &str,
    options: ArtifactSummaryOptions<'_>,
) -> ToolResult<Value> {
    validate_addr(start_addr)?;
    if let Some(end) = options.range_end {
        validate_value("range_end", end)?;
    }
    if let Some(arch) = options.arch {
        validate_r2_setting("arch", arch)?;
    }
    validate_bits(options.bits)?;

    let count = clamp_instructions(options.max_instructions);
    let snapshot = session
        .apply_asm_settings(options.arch, options.bits)
        .await?;
    let ops_result = session.cmdj(format!("pdj {count} @ {start_addr}")).await;
    session.restore_asm_settings(snapshot).await?;
    let ops = ops_result?;
    let ops = match ops {
        Value::Array(arr) => arr,
        _ => Vec::new(),
    };
    build_artifact_summary(start_addr, &ops, &options)
}

/// Build an artifact summary from already-collected r2 instruction objects.
///
/// # Errors
///
/// Returns an error if option values that affect emulation are invalid.
pub fn build_artifact_summary(
    start_addr: &str,
    ops: &[Value],
    options: &ArtifactSummaryOptions<'_>,
) -> ToolResult<Value> {
    let (program, index_by_addr) = build_program(ops, options.range_end.and_then(parse_number));
    let ArtifactEmulation {
        steps,
        decoded_strings,
        calls,
        unsupported,
    } = run_artifact_emulation(&program, &index_by_addr, options);

    Ok(json!({
        "schema": "rbm.r2.artifact_summary.v0",
        "start_addr": start_addr,
        "range_end": options.range_end,
        "arch": options.arch,
        "bits": options.bits,
        "instruction_count": program.len(),
        "executed_steps": steps,
        "step_truncated": steps >= clamp_steps(options.max_steps),
        "decoded_string_count": decoded_strings.len(),
        "decoded_strings": decoded_strings.into_iter().take(200).collect::<Vec<_>>(),
        "call_count": calls.len(),
        "calls": calls.into_iter().take(200).collect::<Vec<_>>(),
        "unsupported": unsupported.into_iter().take(64).collect::<Vec<_>>(),
    }))
}

fn build_program(
    ops: &[Value],
    range_end: Option<u64>,
) -> (Vec<Instruction>, BTreeMap<u64, usize>) {
    let mut program = Vec::new();
    let mut index_by_addr = BTreeMap::new();
    for op in ops {
        let Some(addr) = op.get("addr").and_then(Value::as_u64) else {
            continue;
        };
        if range_end.is_some_and(|end| addr >= end) {
            break;
        }
        let opcode = text_field(op, "opcode");
        let disasm = nonempty(&text_field(op, "disasm"), &opcode).to_string();
        index_by_addr.insert(addr, program.len());
        program.push(Instruction {
            addr,
            opcode,
            disasm,
            kind: text_field(op, "type"),
            jump: op.get("jump").and_then(Value::as_u64),
        });
    }
    (program, index_by_addr)
}

#[derive(Debug)]
struct ArtifactEmulation {
    steps: usize,
    decoded_strings: Vec<Value>,
    calls: Vec<Value>,
    unsupported: Vec<Value>,
}

fn run_artifact_emulation(
    program: &[Instruction],
    index_by_addr: &BTreeMap<u64, usize>,
    options: &ArtifactSummaryOptions<'_>,
) -> ArtifactEmulation {
    let mut emulator = Emulator::new();
    let mut pc = 0usize;
    let mut steps = 0usize;
    let mut unsupported = Vec::new();
    let mut calls = Vec::new();
    let mut context = VecDeque::with_capacity(8);
    let mut first_visit = BTreeMap::<u64, usize>::new();
    let max_steps = clamp_steps(options.max_steps);

    while pc < program.len() && steps < max_steps {
        let ins = &program[pc];
        steps += 1;
        let visit_count = first_visit.entry(ins.addr).or_default();
        *visit_count += 1;
        if *visit_count > 512 {
            unsupported.push(json!({
                "address": fmt_addr(ins.addr),
                "reason": "loop visit cap hit",
                "disassembly": ins.disasm,
            }));
            break;
        }

        if is_call(ins) {
            calls.push(call_summary(ins, &context));
        }

        match emulator.step(ins) {
            StepOutcome::Continue => {
                update_context(&mut context, ins);
                pc += 1;
            }
            StepOutcome::Jump(target) => {
                update_context(&mut context, ins);
                if let Some(next) = index_by_addr.get(&target).copied() {
                    pc = next;
                } else {
                    unsupported.push(json!({
                        "address": fmt_addr(ins.addr),
                        "reason": "jump target outside scanned window",
                        "target": fmt_addr(target),
                        "disassembly": ins.disasm,
                    }));
                    break;
                }
            }
            StepOutcome::Stop(reason) => {
                unsupported.push(json!({
                    "address": fmt_addr(ins.addr),
                    "reason": reason,
                    "disassembly": ins.disasm,
                }));
                break;
            }
        }
    }

    let decoded_strings = sorted_decoded_strings(emulator.decoded_strings(options.min_string_len));
    ArtifactEmulation {
        steps,
        decoded_strings,
        calls,
        unsupported,
    }
}

fn call_summary(ins: &Instruction, context: &VecDeque<String>) -> Value {
    json!({
        "address": fmt_addr(ins.addr),
        "target": ins.jump.map_or_else(|| call_target_text(&ins.opcode), fmt_addr),
        "disassembly": ins.disasm,
        "setup_preview": context_preview(context, 6),
        "pushed_constants": pushed_constants(context, 6),
    })
}

fn sorted_decoded_strings(mut decoded_strings: Vec<Value>) -> Vec<Value> {
    decoded_strings.sort_unstable_by(|left, right| {
        left["address"]
            .as_str()
            .unwrap_or_default()
            .cmp(right["address"].as_str().unwrap_or_default())
            .then(
                left["text"]
                    .as_str()
                    .unwrap_or_default()
                    .cmp(right["text"].as_str().unwrap_or_default()),
            )
    });
    decoded_strings.dedup_by(|left, right| {
        left["address"] == right["address"]
            && left["encoding"] == right["encoding"]
            && left["text"] == right["text"]
    });
    decoded_strings
}

#[derive(Debug)]
struct Instruction {
    addr: u64,
    opcode: String,
    disasm: String,
    kind: String,
    jump: Option<u64>,
}

#[derive(Debug, Clone, Copy, Default)]
struct Flags {
    zf: Option<bool>,
    sf: Option<bool>,
    cf: Option<bool>,
}

#[derive(Debug)]
enum StepOutcome {
    Continue,
    Jump(u64),
    Stop(String),
}

#[derive(Debug)]
struct Emulator {
    regs: BTreeMap<String, u32>,
    memory: BTreeMap<i64, u8>,
    writes: BTreeMap<i64, Vec<String>>,
    flags: Flags,
}

impl Emulator {
    fn new() -> Self {
        let mut regs = BTreeMap::new();
        for reg in ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp"] {
            regs.insert(reg.to_string(), 0);
        }
        regs.insert("esp".to_string(), 0);
        Self {
            regs,
            memory: BTreeMap::new(),
            writes: BTreeMap::new(),
            flags: Flags::default(),
        }
    }

    fn step(&mut self, ins: &Instruction) -> StepOutcome {
        let opcode = trim_comment(&ins.opcode).to_ascii_lowercase();
        if opcode.is_empty() || opcode == "nop" {
            return StepOutcome::Continue;
        }
        if opcode.starts_with("call ") {
            return StepOutcome::Continue;
        }
        if opcode.starts_with("ret") {
            return StepOutcome::Stop("return reached".to_string());
        }
        if let Some(target) = branch_target(&opcode, ins) {
            return self.eval_branch(&opcode, target);
        }
        if opcode.starts_with("push ") {
            let value = self
                .eval_operand(opcode.trim_start_matches("push ").trim())
                .unwrap_or(0);
            let esp = self.reg("esp").wrapping_sub(4);
            self.set_reg("esp", esp);
            self.write_u32(u32_to_i64_signed(esp), value, ins);
            return StepOutcome::Continue;
        }
        if let Some(reg) = opcode.strip_prefix("pop ") {
            let esp = self.reg("esp");
            let value = self.read_u32(u32_to_i64_signed(esp));
            self.set_reg(reg.trim(), value);
            self.set_reg("esp", esp.wrapping_add(4));
            return StepOutcome::Continue;
        }
        if let Some(rest) = opcode.strip_prefix("movzx ") {
            return self.movzx(rest, ins);
        }
        if let Some(rest) = opcode.strip_prefix("mov ") {
            return self.mov(rest, ins);
        }
        if let Some(rest) = opcode.strip_prefix("lea ") {
            return self.lea(rest);
        }
        if let Some(rest) = opcode.strip_prefix("cmp ") {
            return self.cmp(rest);
        }
        if let Some(reg) = opcode.strip_prefix("not ") {
            let reg = reg.trim();
            self.set_reg(reg, !self.reg(reg));
            return StepOutcome::Continue;
        }
        if let Some(reg) = opcode.strip_prefix("inc ") {
            let reg = reg.trim();
            let value = self.reg(reg).wrapping_add(1);
            self.set_reg(reg, value);
            self.flags.zf = Some(value == 0);
            self.flags.sf = Some((value & 0x8000_0000) != 0);
            return StepOutcome::Continue;
        }
        if let Some(reg) = opcode.strip_prefix("dec ") {
            let reg = reg.trim();
            let value = self.reg(reg).wrapping_sub(1);
            self.set_reg(reg, value);
            self.flags.zf = Some(value == 0);
            self.flags.sf = Some((value & 0x8000_0000) != 0);
            return StepOutcome::Continue;
        }
        for mnemonic in ["add", "sub", "xor", "and", "or"] {
            if let Some(rest) = opcode.strip_prefix(&format!("{mnemonic} ")) {
                return self.binary_op(mnemonic, rest);
            }
        }
        if opcode.starts_with("xchg ") {
            let Some((left, right)) = split_operands(opcode.trim_start_matches("xchg ")) else {
                return StepOutcome::Continue;
            };
            let left = left.trim();
            let right = right.trim();
            let a = self.reg(left);
            let b = self.reg(right);
            self.set_reg(left, b);
            self.set_reg(right, a);
            return StepOutcome::Continue;
        }
        if opcode.starts_with("rep ") {
            return StepOutcome::Continue;
        }
        StepOutcome::Continue
    }

    fn mov(&mut self, rest: &str, ins: &Instruction) -> StepOutcome {
        let Some((dst, src)) = split_operands(rest) else {
            return StepOutcome::Continue;
        };
        let dst = dst.trim();
        let src = src.trim();
        let size = explicit_size(dst).unwrap_or(4);
        let clean_dst = strip_size(dst);
        if clean_dst.starts_with('[') {
            if let Some(addr) = self.eval_mem_addr(clean_dst) {
                let value = self.eval_operand(src).unwrap_or(0);
                self.write_value(addr, value, size, ins);
            }
        } else if let Some(value) = self.eval_operand(src) {
            self.set_reg(clean_dst, value);
        }
        StepOutcome::Continue
    }

    fn movzx(&mut self, rest: &str, _ins: &Instruction) -> StepOutcome {
        let Some((dst, src)) = split_operands(rest) else {
            return StepOutcome::Continue;
        };
        let dst = dst.trim();
        let src = strip_size(src.trim());
        let size = explicit_size(rest).unwrap_or(1);
        let value = if src.starts_with('[') {
            self.eval_mem_addr(src)
                .map_or(0, |addr| self.read_value(addr, size))
        } else {
            self.eval_operand(src).unwrap_or(0)
        };
        self.set_reg(dst, value);
        StepOutcome::Continue
    }

    fn lea(&mut self, rest: &str) -> StepOutcome {
        let Some((dst, src)) = split_operands(rest) else {
            return StepOutcome::Continue;
        };
        let src = src.trim();
        if let Some(expr) = src.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            let value = self.eval_expr(expr).unwrap_or(0);
            self.set_reg(dst.trim(), value);
        }
        StepOutcome::Continue
    }

    fn cmp(&mut self, rest: &str) -> StepOutcome {
        let Some((left, right)) = split_operands(rest) else {
            return StepOutcome::Continue;
        };
        let a = self.eval_operand(left.trim()).unwrap_or(0);
        let b = self.eval_operand(right.trim()).unwrap_or(0);
        let result = a.wrapping_sub(b);
        self.flags.zf = Some(a == b);
        self.flags.cf = Some(a < b);
        self.flags.sf = Some((result & 0x8000_0000) != 0);
        StepOutcome::Continue
    }

    fn binary_op(&mut self, op: &str, rest: &str) -> StepOutcome {
        let Some((dst, src)) = split_operands(rest) else {
            return StepOutcome::Continue;
        };
        let dst = dst.trim();
        let src_value = self.eval_operand(src.trim()).unwrap_or(0);
        let size = explicit_size(dst).unwrap_or(4);
        let clean_dst = strip_size(dst);
        let old = if clean_dst.starts_with('[') {
            self.eval_mem_addr(clean_dst)
                .map_or(0, |addr| self.read_value(addr, size))
        } else {
            self.reg(clean_dst)
        };
        let value = match op {
            "add" => old.wrapping_add(src_value),
            "sub" => old.wrapping_sub(src_value),
            "xor" => old ^ src_value,
            "and" => old & src_value,
            "or" => old | src_value,
            _ => old,
        };
        if clean_dst.starts_with('[') {
            if let Some(addr) = self.eval_mem_addr(clean_dst) {
                self.write_value(addr, value, size, &Instruction::synthetic());
            }
        } else {
            self.set_reg(clean_dst, value);
        }
        self.flags.zf = Some(value == 0);
        self.flags.sf = Some((value & 0x8000_0000) != 0);
        StepOutcome::Continue
    }

    fn eval_branch(&self, opcode: &str, target: u64) -> StepOutcome {
        let take = if opcode.starts_with("jmp ") {
            Some(true)
        } else if opcode.starts_with("jne ") || opcode.starts_with("jnz ") {
            self.flags.zf.map(|zf| !zf)
        } else if opcode.starts_with("je ") || opcode.starts_with("jz ") {
            self.flags.zf
        } else if opcode.starts_with("jb ") {
            self.flags.cf
        } else if opcode.starts_with("jae ") || opcode.starts_with("jnb ") {
            self.flags.cf.map(|cf| !cf)
        } else if opcode.starts_with("jns ") {
            self.flags.sf.map(|sf| !sf)
        } else if opcode.starts_with("js ") {
            self.flags.sf
        } else {
            None
        };
        match take {
            Some(true) => StepOutcome::Jump(target),
            Some(false) => StepOutcome::Continue,
            None => StepOutcome::Stop("unsupported or unknown conditional branch".to_string()),
        }
    }

    fn eval_operand(&self, operand: &str) -> Option<u32> {
        let operand = strip_size(operand.trim());
        if operand.starts_with('[') {
            let size = explicit_size(operand).unwrap_or(4);
            return self
                .eval_mem_addr(operand)
                .map(|addr| self.read_value(addr, size));
        }
        if let Some(value) = parse_number(operand) {
            return Some(low_u32(value));
        }
        Some(self.reg(operand))
    }

    fn eval_mem_addr(&self, mem: &str) -> Option<i64> {
        let expr = mem.strip_prefix('[')?.strip_suffix(']')?;
        Some(u32_to_i64_signed(self.eval_expr(expr)?))
    }

    fn eval_expr(&self, expr: &str) -> Option<u32> {
        let normalized = expr
            .replace('-', "+-")
            .replace(['[', ']'], "")
            .replace("ptr", "");
        let mut total = 0u32;
        for raw in normalized.split('+') {
            let term = raw.trim();
            if term.is_empty() {
                continue;
            }
            let value = if let Some((reg, scale)) = term.split_once('*') {
                let scale = low_u32(parse_number(scale.trim())?);
                self.reg(reg.trim()).wrapping_mul(scale)
            } else if let Some(value) = parse_number(term) {
                low_u32(value)
            } else {
                self.reg(term)
            };
            total = total.wrapping_add(value);
        }
        Some(total)
    }

    fn reg(&self, reg: &str) -> u32 {
        let key = full_reg(reg);
        let value = self.regs.get(key).copied().unwrap_or(0);
        match reg.trim() {
            "al" | "cl" | "dl" | "bl" => value & 0xff,
            "ah" | "ch" | "dh" | "bh" => (value >> 8) & 0xff,
            "ax" | "cx" | "dx" | "bx" => value & 0xffff,
            _ => value,
        }
    }

    fn set_reg(&mut self, reg: &str, value: u32) {
        let reg = reg.trim();
        let key = full_reg(reg).to_string();
        let current = self.regs.get(&key).copied().unwrap_or(0);
        let next = match reg {
            "al" | "cl" | "dl" | "bl" => (current & !0xff) | (value & 0xff),
            "ah" | "ch" | "dh" | "bh" => (current & !0xff00) | ((value & 0xff) << 8),
            "ax" | "cx" | "dx" | "bx" => (current & !0xffff) | (value & 0xffff),
            _ => value,
        };
        self.regs.insert(key, next);
    }

    fn write_u32(&mut self, addr: i64, value: u32, ins: &Instruction) {
        self.write_value(addr, value, 4, ins);
    }

    fn write_value(&mut self, addr: i64, value: u32, size: usize, ins: &Instruction) {
        for index in 0..emulated_value_width(size) {
            let byte = u8::try_from((value >> (8 * index)) & 0xff).unwrap_or(0);
            let offset = addr + i64::try_from(index).unwrap_or(i64::MAX);
            self.memory.insert(offset, byte);
            if ins.addr != 0 {
                self.writes.entry(offset).or_default().push(format!(
                    "{} {}",
                    fmt_addr(ins.addr),
                    ins.disasm
                ));
            }
        }
    }

    fn read_value(&self, addr: i64, size: usize) -> u32 {
        let mut value = 0u32;
        for index in 0..emulated_value_width(size) {
            value |= u32::from(
                self.memory
                    .get(&(addr + i64::try_from(index).unwrap_or(i64::MAX)))
                    .copied()
                    .unwrap_or(0),
            ) << (8 * index);
        }
        value
    }

    fn read_u32(&self, addr: i64) -> u32 {
        self.read_value(addr, 4)
    }

    fn decoded_strings(&self, min_len: usize) -> Vec<Value> {
        let mut out = Vec::new();
        let min_len = if min_len == 0 {
            DEFAULT_MIN_STRING
        } else {
            min_len
        };
        for (start, bytes) in contiguous_ranges(&self.memory) {
            for hit in ascii_strings(start, &bytes, min_len) {
                out.push(hit);
            }
            for hit in utf16_strings(start, &bytes, min_len) {
                out.push(hit);
            }
        }
        out
    }
}

impl Instruction {
    const fn synthetic() -> Self {
        Self {
            addr: 0,
            opcode: String::new(),
            disasm: String::new(),
            kind: String::new(),
            jump: None,
        }
    }
}

fn is_call(ins: &Instruction) -> bool {
    ins.kind == "call" || ins.opcode.trim_start().starts_with("call ")
}

fn branch_target(opcode: &str, ins: &Instruction) -> Option<u64> {
    if opcode.starts_with("jmp ") && (opcode.contains('[') || !opcode.contains("0x")) {
        return None;
    }
    if opcode.starts_with("jmp ") || opcode.starts_with('j') {
        return ins.jump.or_else(|| {
            static RE: OnceLock<Regex> = OnceLock::new();
            let re = RE.get_or_init(|| Regex::new(r"(?i)\b0x[0-9a-f]+\b").expect("hex regex"));
            re.find(opcode).and_then(|m| parse_number(m.as_str()))
        });
    }
    None
}

fn split_operands(rest: &str) -> Option<(&str, &str)> {
    rest.split_once(',')
}

fn strip_size(operand: &str) -> &str {
    operand
        .trim()
        .trim_start_matches("byte ")
        .trim_start_matches("word ")
        .trim_start_matches("dword ")
        .trim_start_matches("qword ")
        .trim_start_matches("ptr ")
        .trim()
}

fn explicit_size(text: &str) -> Option<usize> {
    let text = text.trim_start();
    if text.starts_with("byte ") {
        Some(1)
    } else if text.starts_with("word ") {
        Some(2)
    } else if text.starts_with("dword ") {
        Some(4)
    } else if text.starts_with("qword ") {
        Some(8)
    } else {
        None
    }
}

fn full_reg(reg: &str) -> &str {
    match reg.trim() {
        "al" | "ah" | "ax" => "eax",
        "bl" | "bh" | "bx" => "ebx",
        "cl" | "ch" | "cx" => "ecx",
        "dl" | "dh" | "dx" => "edx",
        other => other,
    }
}

fn contiguous_ranges(memory: &BTreeMap<i64, u8>) -> Vec<(i64, Vec<u8>)> {
    let mut ranges = Vec::new();
    let mut start = None;
    let mut last = 0i64;
    let mut buf = Vec::new();
    for (addr, byte) in memory {
        if start.is_none() {
            start = Some(*addr);
            last = *addr;
            buf.push(*byte);
            continue;
        }
        if *addr == last + 1 {
            buf.push(*byte);
            last = *addr;
        } else {
            if let Some(s) = start {
                ranges.push((s, std::mem::take(&mut buf)));
            }
            start = Some(*addr);
            last = *addr;
            buf.push(*byte);
        }
    }
    if let Some(s) = start {
        ranges.push((s, buf));
    }
    ranges
}

fn ascii_strings(start: i64, bytes: &[u8], min_len: usize) -> Vec<Value> {
    let mut out = Vec::new();
    let mut idx = 0usize;
    while idx < bytes.len() {
        while idx < bytes.len() && !is_printable_ascii(bytes[idx]) {
            idx += 1;
        }
        let begin = idx;
        while idx < bytes.len() && is_printable_ascii(bytes[idx]) {
            idx += 1;
        }
        if idx - begin >= min_len {
            let text = String::from_utf8_lossy(&bytes[begin..idx]).to_string();
            out.push(json!({
                "address": format_stack_addr(start + i64::try_from(begin).unwrap_or(i64::MAX)),
                "encoding": "ascii",
                "text": text,
                "byte_count": idx - begin,
            }));
        }
    }
    out
}

fn utf16_strings(start: i64, bytes: &[u8], min_len: usize) -> Vec<Value> {
    let mut out = Vec::new();
    for phase in 0..2 {
        let mut idx = phase;
        while idx + 1 < bytes.len() {
            while idx + 1 < bytes.len() {
                let ch = u16::from_le_bytes([bytes[idx], bytes[idx + 1]]);
                if is_printable_utf16(ch) {
                    break;
                }
                idx += 2;
            }
            let begin = idx;
            let mut chars = Vec::new();
            while idx + 1 < bytes.len() {
                let ch = u16::from_le_bytes([bytes[idx], bytes[idx + 1]]);
                if !is_printable_utf16(ch) {
                    break;
                }
                chars.push(ch);
                idx += 2;
            }
            if chars.len() >= min_len {
                let text = String::from_utf16_lossy(&chars);
                out.push(json!({
                    "address": format_stack_addr(start + i64::try_from(begin).unwrap_or(i64::MAX)),
                    "encoding": "utf16le",
                    "text": text,
                    "byte_count": chars.len() * 2,
                }));
            }
            idx += 2;
        }
    }
    out
}

fn is_printable_ascii(byte: u8) -> bool {
    (0x20..=0x7e).contains(&byte)
}

fn is_printable_utf16(ch: u16) -> bool {
    (0x20..=0x7e).contains(&ch)
}

fn update_context(context: &mut VecDeque<String>, ins: &Instruction) {
    if is_setup_instruction(&ins.opcode) {
        if context.len() == 8 {
            context.pop_front();
        }
        context.push_back(format!("{} {}", fmt_addr(ins.addr), ins.disasm));
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

fn pushed_constants(context: &VecDeque<String>, limit: usize) -> Vec<Value> {
    context
        .iter()
        .rev()
        .take(limit)
        .filter_map(|line| {
            let lower = line.to_ascii_lowercase();
            let idx = lower.find("push ")?;
            let value = parse_number(lower[idx + 5..].trim())?;
            Some(json!({
                "value": fmt_addr(value),
                "setup": line,
            }))
        })
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
        || lower.starts_with("and ")
        || lower.starts_with("or ")
}

fn call_target_text(opcode: &str) -> String {
    opcode
        .trim()
        .strip_prefix("call ")
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn trim_comment(opcode: &str) -> &str {
    opcode.split(';').next().unwrap_or(opcode).trim()
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

fn parse_number(value: &str) -> Option<u64> {
    let raw = value.trim();
    if let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else if let Some(hex) = raw.strip_prefix("-0x").or_else(|| raw.strip_prefix("-0X")) {
        let value = u64::from_str_radix(hex, 16).ok()?;
        Some(u64::from(0u32.wrapping_sub(low_u32(value))))
    } else {
        raw.parse::<i64>().ok().map(|v| u64::from(i64_to_u32(v)))
    }
}

fn low_u32(value: u64) -> u32 {
    u32::try_from(value & u64::from(u32::MAX)).unwrap_or(0)
}

fn i64_to_u32(value: i64) -> u32 {
    let wrapped = value.rem_euclid(1_i64 << 32);
    u32::try_from(wrapped).unwrap_or(0)
}

fn u32_to_i64_signed(value: u32) -> i64 {
    i64::from(i32::from_ne_bytes(value.to_ne_bytes()))
}

fn fmt_addr(value: u64) -> String {
    format!("{value:#x}")
}

fn format_stack_addr(value: i64) -> String {
    if value < 0 {
        format!("-{:#x}", value.unsigned_abs())
    } else {
        format!("{value:#x}")
    }
}

fn clamp_instructions(value: u32) -> u32 {
    if value == 0 {
        DEFAULT_MAX_INSTRUCTIONS
    } else {
        value.min(MAX_INSTRUCTIONS)
    }
}

fn clamp_steps(value: usize) -> usize {
    if value == 0 {
        DEFAULT_MAX_STEPS
    } else {
        value.min(MAX_STEPS)
    }
}

fn emulated_value_width(size: usize) -> usize {
    size.clamp(1, 4)
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

#[cfg(test)]
mod tests {
    use super::{Emulator, Instruction, validate_bits};

    #[test]
    fn bits_zero_uses_r2_default() {
        assert!(validate_bits(0).is_ok());
        assert!(validate_bits(16).is_ok());
        assert!(validate_bits(1).is_err());
    }

    #[test]
    fn emulator_clamps_wide_memory_values_to_u32_width() {
        let mut emulator = Emulator::new();
        let ins = Instruction::synthetic();

        emulator.write_value(0x1000, 0x4433_2211, 8, &ins);

        assert_eq!(emulator.read_value(0x1000, 8), 0x4433_2211);
    }
}
