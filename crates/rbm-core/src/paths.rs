use std::path::{Path, PathBuf};

use crate::error::{ToolError, ToolResult};

#[derive(Debug, Clone)]
pub struct CachePaths {
    root: PathBuf,
}

impl CachePaths {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Build cache paths from `RBM_CACHE_DIR` or default to `./rbinr2-cache/`.
    ///
    /// # Errors
    ///
    /// Returns an error only if `RBM_CACHE_DIR` is set to an empty string.
    pub fn from_env() -> ToolResult<Self> {
        if let Ok(val) = std::env::var("RBM_CACHE_DIR") {
            if val.is_empty() {
                return Err(ToolError::Other("RBM_CACHE_DIR must not be empty".into()));
            }
            return Ok(Self::new(PathBuf::from(val)));
        }
        Ok(Self::new(PathBuf::from("./rbinr2-cache")))
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub fn overflow_dir(&self) -> PathBuf {
        self.root.join("overflow")
    }

    #[must_use]
    pub fn r2_dir(&self) -> PathBuf {
        self.root.join("r2")
    }

    #[must_use]
    pub fn r2_session_dir(&self, sha256: &str) -> PathBuf {
        self.r2_dir().join(sha256)
    }

    #[must_use]
    pub fn tmp_dir(&self) -> PathBuf {
        self.root.join("tmp")
    }

    /// Create all cache subdirectories used by the server.
    ///
    /// # Errors
    ///
    /// Returns an error if any directory cannot be created.
    pub fn ensure_all(&self) -> ToolResult<()> {
        for dir in [self.overflow_dir(), self.r2_dir(), self.tmp_dir()] {
            std::fs::create_dir_all(&dir).map_err(|e| ToolError::io(&dir, e))?;
        }
        Ok(())
    }
}
