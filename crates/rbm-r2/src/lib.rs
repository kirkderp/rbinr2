#![doc = "radare2 backend for rbinr2: session manager and r2_* tool implementations."]

pub mod analyze;
pub mod artifact_summary;
pub mod cmd;
pub mod disasm;
pub mod field_xrefs;
pub mod filters;
pub mod format;
pub mod func_profile;
pub mod jump_table;
pub mod meta;
pub mod navigation;
pub mod path_digest;
pub mod search;
pub mod security;
pub mod session;
pub mod symbols;
pub mod trace;
pub mod types;
pub mod windows_driver;

pub use session::{CloseOutcome, OpenOutcome, Session, SessionManager};
pub mod test_json;
