use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde::Serialize;
use tempfile::Builder as TempBuilder;

use crate::error::{ToolError, ToolResult};

pub const MAX_INLINE_CHARS: usize = 200_000;
pub const OVERFLOW_TTL: Duration = Duration::from_secs(3600);
pub const OVERFLOW_PREFIX: &str = "mcp_";
pub const OVERFLOW_PREVIEW_CHARS: usize = 2000;

#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum GuardedOutput {
    Inline(String),
    Overflow(OverflowSummary),
}

#[derive(Debug, Clone, Serialize)]
pub struct OverflowSummary {
    pub overflow: bool,
    pub message: String,
    pub file_path: PathBuf,
    pub preview: String,
    pub total_chars: usize,
}

#[derive(Debug, Clone)]
pub struct OutputGuard {
    overflow_dir: PathBuf,
    max_inline_chars: usize,
    ttl: Duration,
}

impl OutputGuard {
    pub fn new(overflow_dir: impl Into<PathBuf>) -> Self {
        Self {
            overflow_dir: overflow_dir.into(),
            max_inline_chars: MAX_INLINE_CHARS,
            ttl: OVERFLOW_TTL,
        }
    }

    #[must_use]
    pub const fn with_max_inline_chars(mut self, limit: usize) -> Self {
        self.max_inline_chars = limit;
        self
    }

    #[must_use]
    pub const fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    #[must_use]
    pub fn overflow_dir(&self) -> &Path {
        &self.overflow_dir
    }

    #[must_use]
    pub const fn max_inline_chars(&self) -> usize {
        self.max_inline_chars
    }

    #[must_use]
    pub const fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Guard a string result, returning either inline content or an overflow
    /// summary.
    ///
    /// # Errors
    ///
    /// Returns an error if the overflow file cannot be written.
    pub fn guard_str(&self, _label: &str, content: String) -> ToolResult<GuardedOutput> {
        if content.len() <= self.max_inline_chars {
            return Ok(GuardedOutput::Inline(content));
        }

        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let prefix = format!("{OVERFLOW_PREFIX}{now}_");
        let mut file = TempBuilder::new()
            .prefix(&prefix)
            .tempfile_in(&self.overflow_dir)
            .map_err(|e| ToolError::io(&self.overflow_dir, e))?;

        file.write_all(content.as_bytes())
            .map_err(|e| ToolError::io(file.path(), e))?;

        let (_, persisted) = file
            .keep()
            .map_err(|e| ToolError::io("tempfile keep", std::io::Error::other(e.to_string())))?;

        // Remove expired overflow files
        self.cleanup_expired();

        let preview_len = content.len().min(OVERFLOW_PREVIEW_CHARS);
        let preview_actual = &content[..preview_len];

        Ok(GuardedOutput::Overflow(OverflowSummary {
            overflow: true,
            message: format!(
                "Result too large to inline ({} chars), written to overflow cache",
                content.len()
            ),
            file_path: persisted,
            preview: preview_actual.to_string(),
            total_chars: content.len(),
        }))
    }

    fn cleanup_expired(&self) {
        let now = SystemTime::now();
        if let Ok(dir) = fs::read_dir(&self.overflow_dir) {
            for entry in dir.flatten() {
                if let Ok(meta) = entry.metadata()
                    && meta.is_file()
                    && let Ok(modified) = meta.modified()
                    && now.duration_since(modified).is_ok_and(|age| age > self.ttl)
                {
                    let _ = fs::remove_file(entry.path());
                }
            }
        }
    }
}
