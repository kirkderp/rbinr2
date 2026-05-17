use std::time::Duration;

use crate::env::parse_env_secs;
use crate::error::ToolResult;
use crate::paths::CachePaths;

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub cache: CachePaths,
    pub r2_open_timeout: Duration,
}

impl ServerConfig {
    /// Build server configuration from process environment variables.
    ///
    /// # Errors
    ///
    /// Returns an error if cache path discovery fails.
    pub fn from_env() -> ToolResult<Self> {
        let cache = CachePaths::from_env()?;

        Ok(Self {
            cache,
            r2_open_timeout: Duration::from_secs(parse_env_secs("RBM_R2_OPEN_TIMEOUT", 120)),
        })
    }
}
