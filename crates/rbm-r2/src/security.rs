use rbm_core::ToolResult;
use serde_json::{Map, Value, json};

use crate::session::Session;

const CHECKSEC_FLAGS: &[&str] = &[
    "canary", "nx", "pic", "relro", "stripped", "static", "sanitize",
];
const CHECKSEC_INFO: &[&str] = &["bintype", "bits", "arch"];

/// Return a compact checksec projection from r2 file info.
///
/// # Errors
///
/// Returns an error if the r2 command fails or the response is not valid JSON.
pub async fn checksec(session: &Session) -> ToolResult<Value> {
    let info = session.cmdj("iIj").await?;
    Ok(project_checksec(&info))
}

#[must_use]
pub fn project_checksec(info: &Value) -> Value {
    let Some(obj) = info.as_object() else {
        return Value::Object(Map::new());
    };
    let mut out = Map::new();
    for key in CHECKSEC_FLAGS.iter().chain(CHECKSEC_INFO.iter()) {
        if let Some(value) = obj.get(*key) {
            out.insert((*key).to_string(), value.clone());
        }
    }
    Value::Object(out)
}

pub struct SectionTarget {
    pub name: String,
    pub addr: u64,
    pub size: u64,
}

/// Return per-section entropy estimates using r2's entropy hash command.
///
/// # Errors
///
/// Returns an error if r2 section metadata is not valid JSON or if an entropy
/// command fails.
pub async fn entropy(session: &Session) -> ToolResult<Value> {
    let sections = session.cmdj("iSj").await?;
    let targets = entropy_targets(&sections);
    let mut out: Vec<Value> = Vec::with_capacity(targets.len());
    for target in targets {
        let raw = session
            .cmd(format!("ph entropy {} @ {}", target.size, target.addr))
            .await?;
        out.push(build_entropy_entry(&target, &raw));
    }
    Ok(Value::Array(out))
}

pub fn entropy_targets(sections: &Value) -> Vec<SectionTarget> {
    let Some(arr) = sections.as_array() else {
        return Vec::new();
    };
    let mut out: Vec<SectionTarget> = Vec::new();
    for sec in arr {
        let size = sec.get("size").and_then(Value::as_u64).unwrap_or(0);
        if size == 0 {
            continue;
        }
        let addr = sec
            .get("vaddr")
            .and_then(Value::as_u64)
            .or_else(|| sec.get("paddr").and_then(Value::as_u64))
            .unwrap_or(0);
        let name = sec
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        out.push(SectionTarget { name, addr, size });
    }
    out
}

#[must_use]
pub fn build_entropy_entry(target: &SectionTarget, raw: &str) -> Value {
    let entropy = parse_entropy(raw);
    json!({
        "name": target.name,
        "addr": format!("{:#x}", target.addr),
        "size": target.size,
        "entropy": round4(entropy),
    })
}

#[must_use]
pub fn parse_entropy(raw: &str) -> f64 {
    let parsed = raw.trim().parse::<f64>().unwrap_or(0.0);
    if parsed.is_finite() { parsed } else { 0.0 }
}

#[must_use]
pub fn round4(value: f64) -> f64 {
    (value * 10_000.0).round() / 10_000.0
}
