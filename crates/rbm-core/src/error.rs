use std::path::PathBuf;

use thiserror::Error;

pub type ToolResult<T> = Result<T, ToolError>;

#[derive(Debug, Error)]
pub enum ToolError {
    #[error("tool not implemented yet: {tool}")]
    NotImplemented { tool: &'static str },

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("operation timed out after {seconds}s: {operation}")]
    Timeout { operation: String, seconds: u64 },

    #[error("external binary missing: {binary} ({hint})")]
    ExternalBinaryMissing {
        binary: &'static str,
        hint: &'static str,
    },

    #[error("backend error ({backend}): {message}")]
    Backend {
        backend: &'static str,
        message: String,
    },

    #[error("i/o error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("{0}")]
    Other(String),
}

impl ToolError {
    pub fn backend(backend: &'static str, message: impl Into<String>) -> Self {
        Self::Backend {
            backend,
            message: message.into(),
        }
    }

    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }

    pub fn invalid(msg: impl Into<String>) -> Self {
        Self::InvalidInput(msg.into())
    }

    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::NotFound(msg.into())
    }
}
