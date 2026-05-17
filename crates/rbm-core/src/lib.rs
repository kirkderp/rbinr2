#![doc = "Shared types, errors, and utilities for the rbinr2 workspace."]
#![cfg_attr(test, allow(unsafe_code))]

pub mod config;
pub(crate) mod env;
pub mod error;
pub mod output_guard;
pub mod paths;
pub mod types;
pub mod util;

pub use config::ServerConfig;
pub use error::{ToolError, ToolResult};
pub use output_guard::{GuardedOutput, OutputGuard, OverflowSummary};
pub use paths::CachePaths;
pub use types::{
    BasicBlock, Export, Function, Import, Relocation, Section, Symbol, Xref, XrefKind,
};
pub use util::{IntConvertResult, int_convert};
