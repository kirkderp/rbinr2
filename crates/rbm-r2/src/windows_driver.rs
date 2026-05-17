use std::collections::HashMap;

use rbm_core::{ToolError, ToolResult};
use serde_json::{Value, json};

use crate::disasm::validate_addr;
use crate::session::Session;

const DEFAULT_MAX_INSTRUCTIONS: u64 = 220;
const HARD_MAX_INSTRUCTIONS: u64 = 2_000;

#[derive(Debug, Clone, Copy)]
pub struct DriverDispatchOptions<'a> {
    pub init_addr: &'a str,
    pub driver_register: &'a str,
    pub max_instructions: u64,
}

/// Recover Windows `DRIVER_OBJECT` dispatch/callback assignments from a driver init function.
///
/// # Errors
///
/// Returns an error if the init address is invalid, r2 cannot disassemble the
/// requested window, or r2 returns malformed instruction JSON.
pub async fn windows_driver_dispatch(
    session: &Session,
    options: DriverDispatchOptions<'_>,
) -> ToolResult<Value> {
    validate_addr(options.init_addr)?;
    let driver_register = normalize_register(options.driver_register).ok_or_else(|| {
        ToolError::invalid(format!(
            "driver_register must be an x64 general-purpose register, got {:?}",
            options.driver_register
        ))
    })?;
    let max_instructions = normalize_max_instructions(options.max_instructions);
    let instructions = disassemble_window(session, options.init_addr, max_instructions).await?;

    let assignments = collect_driver_assignments(&instructions, driver_register);
    let notify_callbacks = collect_notify_callbacks(&instructions);
    let suggested_targets = suggested_targets(&assignments, &notify_callbacks);

    Ok(json!({
        "schema": "rbm.r2.windows_driver_dispatch.v0",
        "init_addr": options.init_addr,
        "driver_register": driver_register,
        "instruction_count": instructions.len(),
        "max_instructions": max_instructions,
        "driver_object_layout": {
            "arch": "x64",
            "driver_unload_offset": "0x68",
            "major_function_base_offset": "0x70",
            "major_function_entry_size": 8,
            "source": "Windows DRIVER_OBJECT x64 layout"
        },
        "dispatch_assignments": assignments,
        "notify_callbacks": notify_callbacks,
        "suggested_disassembly_targets": suggested_targets,
        "notes": [
            "Heuristic scan: tracks nearby immediate/code-pointer loads into registers and stores into [driver_register + offset].",
            "Dispatch target semantics require follow-up disassembly; this tool classifies DRIVER_OBJECT slots only.",
            "Use IRP_MJ_DEVICE_CONTROL slot as the IOCTL-dispatch anchor when present, but do not infer IOCTL behavior without handler analysis."
        ]
    }))
}

fn normalize_max_instructions(count: u64) -> u64 {
    if count == 0 {
        DEFAULT_MAX_INSTRUCTIONS
    } else {
        count.min(HARD_MAX_INSTRUCTIONS)
    }
}

fn normalize_register(register: &str) -> Option<&str> {
    let trimmed = register.trim();
    if trimmed.is_empty() {
        return Some("rcx");
    }
    match trimmed.to_ascii_lowercase().as_str() {
        "rax" => Some("rax"),
        "rbx" => Some("rbx"),
        "rcx" => Some("rcx"),
        "rdx" => Some("rdx"),
        "rsi" => Some("rsi"),
        "rdi" => Some("rdi"),
        "rbp" => Some("rbp"),
        "rsp" => Some("rsp"),
        "r8" => Some("r8"),
        "r9" => Some("r9"),
        "r10" => Some("r10"),
        "r11" => Some("r11"),
        "r12" => Some("r12"),
        "r13" => Some("r13"),
        "r14" => Some("r14"),
        "r15" => Some("r15"),
        _ => None,
    }
}

async fn disassemble_window(
    session: &Session,
    init_addr: &str,
    max_instructions: u64,
) -> ToolResult<Vec<InstructionRow>> {
    let value = crate::disasm::disassemble_json(session, init_addr, max_instructions).await?;
    let Some(items) = value.get("ops").and_then(Value::as_array) else {
        return Err(ToolError::invalid(
            "r2 disassembly result did not contain an ops array",
        ));
    };
    Ok(items
        .iter()
        .filter_map(InstructionRow::from_value)
        .collect())
}

#[derive(Debug, Clone)]
struct InstructionRow {
    offset: u64,
    opcode: String,
    disasm: String,
}

impl InstructionRow {
    fn from_value(value: &Value) -> Option<Self> {
        let offset = value
            .get("offset")
            .and_then(Value::as_u64)
            .or_else(|| parse_hex_u64(value.get("addr")?.as_str()?))?;
        let opcode = value
            .get("opcode")
            .or_else(|| value.get("disasm"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let disasm = value
            .get("disasm")
            .or_else(|| value.get("opcode"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        Some(Self {
            offset,
            opcode,
            disasm,
        })
    }

    fn text(&self) -> &str {
        if self.disasm.is_empty() {
            &self.opcode
        } else {
            &self.disasm
        }
    }
}

fn collect_driver_assignments(
    instructions: &[InstructionRow],
    driver_register: &str,
) -> Vec<Value> {
    let mut reg_values: HashMap<String, String> = HashMap::new();
    let mut out = Vec::new();
    for ins in instructions {
        let text = normalize_instruction(ins.text());
        if let Some((reg, target)) = parse_lea_code_pointer(&text) {
            reg_values.insert(reg, target);
        }
        if let Some((offset, source)) = parse_driver_store(&text, driver_register) {
            let source_target = normalize_register_token(&source)
                .and_then(|reg| reg_values.get(reg).cloned())
                .or_else(|| parse_hex_address(&source));
            out.push(json!({
                "write_address": format!("{:#x}", ins.offset),
                "driver_object_offset": format!("{offset:#x}"),
                "slot": driver_object_slot(offset),
                "major_function_index": major_function_index(offset),
                "source": source,
                "target_address": source_target.clone(),
                "instruction": ins.text(),
                "follow_up": source_target.as_ref().map(|target| json!({
                    "tool": "r2_disassemble",
                    "arguments": {
                        "addr": target,
                        "count": 96,
                        "format": "text",
                        "function": false
                    }
                }))
            }));
        }
    }
    out
}

fn collect_notify_callbacks(instructions: &[InstructionRow]) -> Vec<Value> {
    let mut reg_values: HashMap<String, String> = HashMap::new();
    let mut out = Vec::new();
    for ins in instructions {
        let text = normalize_instruction(ins.text());
        if let Some((reg, target)) = parse_lea_code_pointer(&text) {
            reg_values.insert(reg, target);
        }
        if !text.contains("psset") || !text.contains("notifyroutine") || !text.starts_with("call ")
        {
            continue;
        }
        let callback = reg_values
            .get("rcx")
            .cloned()
            .or_else(|| nearest_register_value(&reg_values, "ecx"));
        out.push(json!({
            "call_address": format!("{:#x}", ins.offset),
            "api": notify_api_name(&text),
            "callback_address": callback,
            "instruction": ins.text(),
            "follow_up": callback.as_ref().map(|target| json!({
                "tool": "r2_disassemble",
                "arguments": {
                    "addr": target,
                    "count": 128,
                    "format": "text",
                    "function": false
                }
            }))
        }));
    }
    out
}

fn suggested_targets(assignments: &[Value], callbacks: &[Value]) -> Vec<Value> {
    let mut out = Vec::new();
    for item in assignments.iter().chain(callbacks.iter()) {
        let Some(target) = item
            .get("target_address")
            .or_else(|| item.get("callback_address"))
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
        else {
            continue;
        };
        let kind = item
            .get("slot")
            .or_else(|| item.get("api"))
            .and_then(Value::as_str)
            .unwrap_or("callback_or_dispatch");
        if out
            .iter()
            .any(|row: &Value| row.get("addr").and_then(Value::as_str) == Some(target))
        {
            continue;
        }
        out.push(json!({
            "addr": target,
            "kind": kind,
            "tool": "r2_disassemble",
            "arguments": {
                "addr": target,
                "count": 128,
                "format": "text",
                "function": false
            }
        }));
    }
    out
}

fn normalize_instruction(text: &str) -> String {
    text.to_ascii_lowercase()
        .replace("qword ptr ", "qword ")
        .replace("dword ptr ", "dword ")
}

fn parse_lea_code_pointer(text: &str) -> Option<(String, String)> {
    let rest = text.strip_prefix("lea ")?;
    let (reg, rhs) = rest.split_once(',')?;
    let target = parse_hex_address(rhs)?;
    Some((normalize_register_token(reg)?.to_string(), target))
}

fn parse_driver_store(text: &str, driver_register: &str) -> Option<(u64, String)> {
    let rest = text.strip_prefix("mov qword ")?;
    let (lhs, rhs) = rest.split_once(',')?;
    let offset = parse_driver_offset(lhs, driver_register)?;
    Some((offset, rhs.trim().to_string()))
}

fn parse_driver_offset(operand: &str, driver_register: &str) -> Option<u64> {
    let operand = operand.trim();
    let inner = operand.strip_prefix('[')?.strip_suffix(']')?;
    let compact = inner.replace(' ', "");
    if compact == driver_register {
        return Some(0);
    }
    let prefix = format!("{driver_register}+");
    let value = compact.strip_prefix(&prefix)?;
    parse_int(value)
}

fn parse_hex_address(text: &str) -> Option<String> {
    parse_hex_u64(text).map(|parsed| format!("{parsed:#x}"))
}

fn parse_hex_u64(text: &str) -> Option<u64> {
    for token in text.split(|c: char| !(c.is_ascii_hexdigit() || c == 'x' || c == 'X')) {
        if let Some(value) = token.strip_prefix("0x")
            && value.len() >= 6
            && value.chars().all(|c| c.is_ascii_hexdigit())
        {
            let parsed = u64::from_str_radix(value, 16).ok()?;
            return Some(parsed);
        }
    }
    None
}

fn parse_int(text: &str) -> Option<u64> {
    text.strip_prefix("0x").map_or_else(
        || text.parse::<u64>().ok(),
        |value| u64::from_str_radix(value, 16).ok(),
    )
}

fn normalize_register_token(token: &str) -> Option<&str> {
    match token.trim().trim_start_matches('%') {
        "rax" | "eax" | "ax" | "al" => Some("rax"),
        "rbx" | "ebx" | "bx" | "bl" => Some("rbx"),
        "rcx" | "ecx" | "cx" | "cl" => Some("rcx"),
        "rdx" | "edx" | "dx" | "dl" => Some("rdx"),
        "rsi" | "esi" | "si" | "sil" => Some("rsi"),
        "rdi" | "edi" | "di" | "dil" => Some("rdi"),
        "rbp" | "ebp" | "bp" | "bpl" => Some("rbp"),
        "rsp" | "esp" | "sp" | "spl" => Some("rsp"),
        "r8" | "r8d" | "r8w" | "r8b" => Some("r8"),
        "r9" | "r9d" | "r9w" | "r9b" => Some("r9"),
        "r10" | "r10d" | "r10w" | "r10b" => Some("r10"),
        "r11" | "r11d" | "r11w" | "r11b" => Some("r11"),
        "r12" | "r12d" | "r12w" | "r12b" => Some("r12"),
        "r13" | "r13d" | "r13w" | "r13b" => Some("r13"),
        "r14" | "r14d" | "r14w" | "r14b" => Some("r14"),
        "r15" | "r15d" | "r15w" | "r15b" => Some("r15"),
        _ => None,
    }
}

fn nearest_register_value(values: &HashMap<String, String>, register: &str) -> Option<String> {
    normalize_register_token(register).and_then(|reg| values.get(reg).cloned())
}

const fn driver_object_slot(offset: u64) -> &'static str {
    match offset {
        0x58 => "DriverInit",
        0x60 => "DriverStartIo",
        0x68 => "DriverUnload",
        0x70 => "IRP_MJ_CREATE",
        0x78 => "IRP_MJ_CREATE_NAMED_PIPE",
        0x80 => "IRP_MJ_CLOSE",
        0x88 => "IRP_MJ_READ",
        0x90 => "IRP_MJ_WRITE",
        0x98 => "IRP_MJ_QUERY_INFORMATION",
        0xa0 => "IRP_MJ_SET_INFORMATION",
        0xa8 => "IRP_MJ_QUERY_EA",
        0xb0 => "IRP_MJ_SET_EA",
        0xb8 => "IRP_MJ_FLUSH_BUFFERS",
        0xc0 => "IRP_MJ_QUERY_VOLUME_INFORMATION",
        0xc8 => "IRP_MJ_SET_VOLUME_INFORMATION",
        0xd0 => "IRP_MJ_DIRECTORY_CONTROL",
        0xd8 => "IRP_MJ_FILE_SYSTEM_CONTROL",
        0xe0 => "IRP_MJ_DEVICE_CONTROL",
        0xe8 => "IRP_MJ_INTERNAL_DEVICE_CONTROL",
        0xf0 => "IRP_MJ_SHUTDOWN",
        0xf8 => "IRP_MJ_LOCK_CONTROL",
        0x100 => "IRP_MJ_CLEANUP",
        0x108 => "IRP_MJ_CREATE_MAILSLOT",
        0x110 => "IRP_MJ_QUERY_SECURITY",
        0x118 => "IRP_MJ_SET_SECURITY",
        0x120 => "IRP_MJ_POWER",
        0x128 => "IRP_MJ_SYSTEM_CONTROL",
        0x130 => "IRP_MJ_DEVICE_CHANGE",
        0x138 => "IRP_MJ_QUERY_QUOTA",
        0x140 => "IRP_MJ_SET_QUOTA",
        0x148 => "IRP_MJ_PNP",
        _ => "UNKNOWN_DRIVER_OBJECT_FIELD",
    }
}

fn major_function_index(offset: u64) -> Option<u64> {
    if (0x70..=0x148).contains(&offset) && (offset - 0x70).is_multiple_of(8) {
        Some((offset - 0x70) / 8)
    } else {
        None
    }
}

fn notify_api_name(text: &str) -> &'static str {
    if text.contains("pssetcreateprocessnotifyroutine") {
        "PsSetCreateProcessNotifyRoutine"
    } else if text.contains("pssetloadimagenotifyroutine") {
        "PsSetLoadImageNotifyRoutine"
    } else if text.contains("pssetcreatethreadnotifyroutine") {
        "PsSetCreateThreadNotifyRoutine"
    } else {
        "UNKNOWN_NOTIFY_ROUTINE"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(offset: u64, opcode: &str) -> InstructionRow {
        InstructionRow {
            offset,
            opcode: opcode.to_string(),
            disasm: opcode.to_string(),
        }
    }

    #[test]
    fn maps_driver_object_major_function_offsets() {
        assert_eq!(driver_object_slot(0x68), "DriverUnload");
        assert_eq!(driver_object_slot(0x70), "IRP_MJ_CREATE");
        assert_eq!(driver_object_slot(0x80), "IRP_MJ_CLOSE");
        assert_eq!(driver_object_slot(0xe0), "IRP_MJ_DEVICE_CONTROL");
        assert_eq!(major_function_index(0xe0), Some(14));
        assert_eq!(major_function_index(0x68), None);
    }

    #[test]
    fn recovers_dispatch_assignments_from_lea_then_store() {
        let instructions = vec![
            row(0x0001_8000_e084, "lea rax, [0x18000e0d0]"),
            row(0x0001_8000_e08e, "mov qword [rbx + 0x70], rax"),
            row(0x0001_8000_e092, "mov qword [rbx + 0x80], rax"),
            row(0x0001_8000_e099, "lea rax, [0x18000de40]"),
            row(0x0001_8000_e0a0, "mov qword [rbx + 0xe0], rax"),
        ];

        let assignments = collect_driver_assignments(&instructions, "rbx");

        assert_eq!(assignments.len(), 3);
        assert_eq!(assignments[0]["slot"], "IRP_MJ_CREATE");
        assert_eq!(assignments[0]["target_address"], "0x18000e0d0");
        assert_eq!(assignments[1]["slot"], "IRP_MJ_CLOSE");
        assert_eq!(assignments[2]["slot"], "IRP_MJ_DEVICE_CONTROL");
        assert_eq!(assignments[2]["major_function_index"], 14);
        assert_eq!(assignments[2]["target_address"], "0x18000de40");
    }

    #[test]
    fn recovers_notify_callback_from_rcx_setup() {
        let instructions = vec![
            row(0x0001_8000_e01b, "lea rcx, [0x18000e930]"),
            row(
                0x0001_8000_e022,
                "call qword [sym.imp.ntoskrnl.exe_PsSetCreateProcessNotifyRoutine]",
            ),
            row(0x0001_8000_e036, "lea rcx, [0x18000e390]"),
            row(
                0x0001_8000_e044,
                "call sub.ntoskrnl.exe_PsSetLoadImageNotifyRoutine",
            ),
        ];

        let callbacks = collect_notify_callbacks(&instructions);

        assert_eq!(callbacks.len(), 2);
        assert_eq!(callbacks[0]["api"], "PsSetCreateProcessNotifyRoutine");
        assert_eq!(callbacks[0]["callback_address"], "0x18000e930");
        assert_eq!(callbacks[1]["api"], "PsSetLoadImageNotifyRoutine");
        assert_eq!(callbacks[1]["callback_address"], "0x18000e390");
    }
}
