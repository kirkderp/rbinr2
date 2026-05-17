/// Support functions for the r2 MCP server.
use std::fs;
use std::path::{Path, PathBuf};

use rbm_core::{GuardedOutput, OutputGuard, ToolError, ToolResult};
use rmcp::ErrorData;
use serde_json::Value;
use sha2::{Digest, Sha256};

pub(crate) const R2_CMD_MAX_INLINE_CHARS: usize = 20_000;
const EXTRACT_PREVIEW_BYTES: usize = 256;

pub(crate) struct ExtractBytesResultInput<'a> {
    pub binary_path: &'a str,
    pub addr: &'a str,
    pub requested_count: u64,
    pub hex_text: &'a str,
    pub out_path: Option<&'a str>,
    pub overwrite: bool,
    pub lookup: &'a Value,
    pub mapping: &'a Value,
}

/// Apply the stricter raw-command inline cap used by `r2_cmd`.
///
/// # Errors
///
/// Returns an error if the guarded overflow payload cannot be written.
pub(crate) fn guard_r2_cmd_output(guard: &OutputGuard, raw: String) -> ToolResult<GuardedOutput> {
    OutputGuard::new(guard.overflow_dir().to_path_buf())
        .with_max_inline_chars(R2_CMD_MAX_INLINE_CHARS)
        .with_ttl(guard.ttl())
        .guard_str("r2_cmd", raw)
}

/// Build the structured response for `r2_extract_bytes`.
///
/// # Errors
///
/// Returns an error if r2 returned malformed hex bytes or if optional write-out
/// to `out_path` fails.
pub(crate) fn build_extract_bytes_result(input: &ExtractBytesResultInput<'_>) -> ToolResult<Value> {
    let bytes = decode_r2_hex_bytes(input.hex_text)?;
    let sha256 = format!("{:x}", Sha256::digest(&bytes));
    let write = write_extracted_bytes(input.out_path, &bytes, input.overwrite, &sha256)?;
    Ok(serde_json::json!({
        "schema": "rbm.r2.extract_bytes.v0",
        "binary_path": input.binary_path,
        "addr": input.addr,
        "requested_count": input.requested_count,
        "byte_count": bytes.len(),
        "sha256": sha256,
        "preview_len": bytes.len().min(EXTRACT_PREVIEW_BYTES),
        "hex_preview": hex_preview(&bytes),
        "hex_preview_truncated": bytes.len() > EXTRACT_PREVIEW_BYTES,
        "hex_tail_preview": hex_tail_preview(&bytes),
        "hex_tail_preview_truncated": bytes.len() > EXTRACT_PREVIEW_BYTES,
        "ascii_preview": ascii_preview(&bytes),
        "ascii_preview_truncated": bytes.len() > EXTRACT_PREVIEW_BYTES,
        "lookup": input.lookup,
        "mapping": input.mapping,
        "write": write,
        "written_path": write.get("path").and_then(Value::as_str),
        "written_sha256": write.get("sha256").and_then(Value::as_str),
    }))
}

fn decode_r2_hex_bytes(hex_text: &str) -> ToolResult<Vec<u8>> {
    let compact: String = hex_text.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.is_empty() {
        return Ok(Vec::new());
    }
    if !compact.len().is_multiple_of(2) {
        return Err(ToolError::invalid(
            "r2 returned an odd-length hex byte string",
        ));
    }
    hex::decode(&compact).map_err(|e| ToolError::invalid(format!("r2 returned invalid hex: {e}")))
}

fn write_extracted_bytes(
    out_path: Option<&str>,
    bytes: &[u8],
    overwrite: bool,
    sha256: &str,
) -> ToolResult<Value> {
    let Some(path) = out_path.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(serde_json::json!({
            "requested": false,
            "path": null,
            "written": false,
            "overwrote": false,
            "sha256": null,
            "parent_exists": null,
            "parent_writable": null,
        }));
    };
    let path = PathBuf::from(path);
    let existed = path.exists();
    if existed && !overwrite {
        let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
        return Err(ToolError::invalid(format!(
            "out_path exists and overwrite=false: {}; parent_exists={:?}; parent_writable={:?}",
            path.display(),
            parent.map(Path::exists),
            parent.map(is_writable_dir)
        )));
    }
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent).map_err(|e| {
            ToolError::io(
                parent,
                std::io::Error::new(
                    e.kind(),
                    format!(
                        "failed to create parent {}; exists={}; writable={}",
                        parent.display(),
                        parent.exists(),
                        is_writable_dir(parent)
                    ),
                ),
            )
        })?;
    }
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    let parent_exists = parent.is_some_and(Path::exists);
    let parent_writable = parent.is_some_and(is_writable_dir);
    fs::write(&path, bytes).map_err(|e| ToolError::io(&path, e))?;
    Ok(serde_json::json!({
        "requested": true,
        "path": path.to_string_lossy().into_owned(),
        "written": true,
        "overwrote": existed,
        "sha256": sha256,
        "parent_exists": parent_exists,
        "parent_writable": parent_writable,
    }))
}

fn hex_preview(bytes: &[u8]) -> String {
    hex::encode(&bytes[..bytes.len().min(EXTRACT_PREVIEW_BYTES)])
}

fn hex_tail_preview(bytes: &[u8]) -> String {
    let begin = bytes.len().saturating_sub(EXTRACT_PREVIEW_BYTES);
    hex::encode(&bytes[begin..])
}

fn ascii_preview(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(EXTRACT_PREVIEW_BYTES)
        .map(|byte| {
            if byte.is_ascii_graphic() || *byte == b' ' {
                char::from(*byte)
            } else {
                '.'
            }
        })
        .collect()
}

fn is_writable_dir(path: &Path) -> bool {
    path.metadata()
        .is_ok_and(|meta| meta.is_dir() && !meta.permissions().readonly())
}

#[must_use]
pub(crate) fn build_address_mapping(addr_value: Option<u64>, sections: &Value) -> Value {
    let Some(addr_value) = addr_value else {
        return serde_json::json!({
            "address": null,
            "section": null,
            "section_vaddr": null,
            "section_paddr": null,
            "section_size": null,
            "file_offset": null,
        });
    };
    let section = sections.as_array().and_then(|items| {
        items.iter().find(|item| {
            let vaddr = item
                .get("vaddr")
                .or_else(|| item.get("addr"))
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let size = item
                .get("vsize")
                .or_else(|| item.get("size"))
                .and_then(Value::as_u64)
                .unwrap_or(0);
            size > 0 && addr_value >= vaddr && addr_value < vaddr.saturating_add(size)
        })
    });
    let Some(section) = section else {
        return serde_json::json!({
            "address": format!("{addr_value:#x}"),
            "section": null,
            "section_vaddr": null,
            "section_paddr": null,
            "section_size": null,
            "file_offset": null,
        });
    };
    let vaddr = section
        .get("vaddr")
        .or_else(|| section.get("addr"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let paddr = section
        .get("paddr")
        .or_else(|| section.get("offset"))
        .and_then(Value::as_u64);
    let size = section
        .get("vsize")
        .or_else(|| section.get("size"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let file_offset = paddr.map(|paddr| paddr.saturating_add(addr_value.saturating_sub(vaddr)));
    serde_json::json!({
        "address": format!("{addr_value:#x}"),
        "section": section
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or(""),
        "section_vaddr": format!("{vaddr:#x}"),
        "section_paddr": paddr.map(|value| format!("{value:#x}")),
        "section_size": format!("{size:#x}"),
        "file_offset": file_offset.map(|value| format!("{value:#x}")),
    })
}

pub(crate) fn apply_name_filter(value: Value, filter: Option<&str>) -> Result<Value, ErrorData> {
    let Some(pattern) = filter.filter(|s| !s.is_empty()) else {
        return Ok(value);
    };
    rbm_r2::symbols::filter_by_name(value, pattern)
        .map_err(|e| ErrorData::new(rmcp::model::ErrorCode::INTERNAL_ERROR, e.to_string(), None))
}
