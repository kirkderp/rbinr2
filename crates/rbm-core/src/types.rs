use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Section {
    pub name: String,
    pub vaddr: u64,
    pub size: u64,
    pub vsize: u64,
    pub perm: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entropy: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Import {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub library: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plt: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ordinal: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Export {
    pub name: String,
    pub vaddr: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Symbol {
    pub name: String,
    pub vaddr: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Function {
    pub name: String,
    pub vaddr: u64,
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callrefs: Option<Vec<u64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbbs: Option<u32>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BasicBlock {
    pub addr: u64,
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jump: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fail: Option<u64>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum XrefKind {
    Call,
    Data,
    Code,
    String,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Xref {
    pub from: u64,
    pub to: u64,
    pub kind: XrefKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Relocation {
    pub vaddr: u64,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
}
