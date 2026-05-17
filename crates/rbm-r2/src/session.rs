use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use dashmap::DashMap;
use rbm_core::{ToolError, ToolResult};
use serde::Serialize;
use serde_json::Value;
use tokio::sync::{mpsc, oneshot};

use r2pipe::{R2Pipe, R2PipeSpawnOptions};

const DEFAULT_OPEN_TIMEOUT: Duration = Duration::from_secs(120);
const STARTUP_ANALYSIS_COMMANDS: [Option<&str>; 3] = [Some("aaa"), Some("aa"), None];

enum SessionCmd {
    Cmd {
        cmd: String,
        reply: oneshot::Sender<Result<String, String>>,
    },
    Cmdj {
        cmd: String,
        reply: oneshot::Sender<Result<Value, String>>,
    },
    Shutdown,
}

pub struct Session {
    binary_path: PathBuf,
    tx: mpsc::UnboundedSender<SessionCmd>,
    tool_timeout: Duration,
}

#[derive(Debug, Default)]
pub struct AsmSettingsSnapshot {
    arch: Option<String>,
    bits: Option<String>,
}

impl Session {
    #[must_use]
    pub fn binary_path(&self) -> &Path {
        &self.binary_path
    }

    /// Request shutdown of the r2 worker thread.
    ///
    /// This is explicit so `r2_close` can stop a session even if concurrent
    /// tool handlers still hold cloned `Arc<Session>` references.
    #[must_use]
    pub fn shutdown(&self) -> bool {
        self.tx.send(SessionCmd::Shutdown).is_ok()
    }

    /// Run a text r2 command on this session.
    ///
    /// # Errors
    ///
    /// Returns an error if the session worker has shut down, if the reply channel
    /// is dropped, or if r2 rejects the command.
    pub async fn cmd(&self, cmd: impl Into<String>) -> ToolResult<String> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(SessionCmd::Cmd {
                cmd: cmd.into(),
                reply: reply_tx,
            })
            .map_err(|_| ToolError::backend("r2", "session worker channel closed"))?;
        tokio::time::timeout(self.tool_timeout, reply_rx)
            .await
            .map_err(|_| {
                ToolError::backend(
                    "r2",
                    format!(
                        "r2 command timed out after {}s",
                        self.tool_timeout.as_secs()
                    ),
                )
            })?
            .map_err(|_| ToolError::backend("r2", "session reply channel dropped"))?
            .map_err(|e| ToolError::backend("r2", e))
    }

    /// Run an r2 command and decode the response as JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if the session worker has shut down, if r2 rejects the
    /// command, or if the response is not valid JSON.
    pub async fn cmdj(&self, cmd: impl Into<String>) -> ToolResult<Value> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(SessionCmd::Cmdj {
                cmd: cmd.into(),
                reply: reply_tx,
            })
            .map_err(|_| ToolError::backend("r2", "session worker channel closed"))?;
        tokio::time::timeout(self.tool_timeout, reply_rx)
            .await
            .map_err(|_| {
                ToolError::backend(
                    "r2",
                    format!(
                        "r2 command timed out after {}s",
                        self.tool_timeout.as_secs()
                    ),
                )
            })?
            .map_err(|_| ToolError::backend("r2", "session reply channel dropped"))?
            .map_err(|e| ToolError::backend("r2", e))
    }

    /// Apply temporary disassembly settings and return the previous values.
    ///
    /// Call `restore_asm_settings` before returning to keep persistent sessions
    /// from leaking architecture overrides into later tool calls.
    ///
    /// # Errors
    ///
    /// Returns an error if reading or applying an r2 asm setting fails.
    pub async fn apply_asm_settings(
        &self,
        arch: Option<&str>,
        bits: u32,
    ) -> ToolResult<AsmSettingsSnapshot> {
        let mut snapshot = AsmSettingsSnapshot::default();
        if let Some(arch) = arch {
            snapshot.arch = Some(self.cmd("e asm.arch").await?.trim().to_string());
            self.cmd(format!("e asm.arch={arch}")).await?;
        }
        if bits != 0 {
            snapshot.bits = Some(self.cmd("e asm.bits").await?.trim().to_string());
            self.cmd(format!("e asm.bits={bits}")).await?;
        }
        Ok(snapshot)
    }

    /// Restore settings captured by `apply_asm_settings`.
    ///
    /// # Errors
    ///
    /// Returns an error if restoring an r2 asm setting fails.
    pub async fn restore_asm_settings(&self, snapshot: AsmSettingsSnapshot) -> ToolResult<()> {
        if let Some(bits) = snapshot.bits {
            self.cmd(format!("e asm.bits={bits}")).await?;
        }
        if let Some(arch) = snapshot.arch {
            self.cmd(format!("e asm.arch={arch}")).await?;
        }
        Ok(())
    }

    async fn spawn(binary_path: PathBuf, tool_timeout: Duration) -> ToolResult<Arc<Self>> {
        let (tx, mut rx) = mpsc::unbounded_channel::<SessionCmd>();
        let (init_tx, init_rx) = oneshot::channel::<Result<(), String>>();
        let thread_path = binary_path.clone();

        thread::Builder::new()
            .name(format!(
                "rbm-r2-session-{}",
                thread_path
                    .file_name()
                    .map_or_else(|| "unknown".into(), |s| s.to_string_lossy().into_owned())
            ))
            .spawn(move || {
                let mut pipe = match spawn_with_startup_analysis(&thread_path) {
                    Ok(p) => p,
                    Err(e) => {
                        let _ = init_tx.send(Err(e));
                        return;
                    }
                };
                if init_tx.send(Ok(())).is_err() {
                    pipe.close();
                    return;
                }

                while let Some(msg) = rx.blocking_recv() {
                    match msg {
                        SessionCmd::Cmd { cmd, reply } => {
                            let result = pipe.cmd(&cmd).map_err(|e| e.to_string());
                            let _ = reply.send(result);
                        }
                        SessionCmd::Cmdj { cmd, reply } => {
                            let result = (|| -> Result<Value, String> {
                                let raw = pipe.cmd(&cmd).map_err(|e| e.to_string())?;
                                let trimmed = raw.trim();
                                if trimmed.is_empty() {
                                    return Ok(Value::Null);
                                }
                                serde_json::from_str(trimmed)
                                    .map_err(|e| format!("Serde deserialization error: {e}"))
                            })();
                            let _ = reply.send(result);
                        }
                        SessionCmd::Shutdown => break,
                    }
                }
                pipe.close();
            })
            .map_err(|e| {
                ToolError::backend("r2", format!("failed to spawn session worker thread: {e}"))
            })?;

        init_rx
            .await
            .map_err(|_| ToolError::backend("r2", "session init channel dropped"))?
            .map_err(|e| ToolError::backend("r2", e))?;

        Ok(Self {
            binary_path,
            tx,
            tool_timeout,
        }
        .into())
    }
}

fn spawn_with_startup_analysis(path: &Path) -> Result<R2Pipe, String> {
    let mut errors = Vec::new();
    for command in STARTUP_ANALYSIS_COMMANDS {
        match spawn_once(path, command) {
            Ok(pipe) => return Ok(pipe),
            Err(err) => errors.push(err),
        }
    }

    Err(format!(
        "r2 startup analysis failed for all configured commands: {}",
        errors.join("; ")
    ))
}

fn spawn_once(path: &Path, analysis_command: Option<&str>) -> Result<R2Pipe, String> {
    let path_str = path.to_string_lossy().into_owned();
    let opts = R2PipeSpawnOptions {
        exepath: "r2".to_string(),
        args: vec!["-2"],
    };
    let mut pipe = R2Pipe::spawn(path_str.as_str(), Some(opts))
        .map_err(|e| format!("r2 spawn failed: {e}"))?;

    if let Some(command) = analysis_command
        && let Err(e) = pipe.cmd(command)
    {
        pipe.close();
        return Err(format!("r2 {command} failed: {e}"));
    }

    Ok(pipe)
}

#[must_use]
pub fn startup_analysis_commands() -> Vec<&'static str> {
    STARTUP_ANALYSIS_COMMANDS
        .iter()
        .map(|command| command.unwrap_or("none"))
        .collect()
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.tx.send(SessionCmd::Shutdown);
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct OpenOutcome {
    pub status: &'static str,
    pub binary: PathBuf,
    pub info: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct CloseOutcome {
    pub closed: bool,
    pub binary: PathBuf,
}

pub struct SessionManager {
    sessions: DashMap<PathBuf, Arc<Session>>,
    aliases: DashMap<PathBuf, PathBuf>,
    open_timeout: Duration,
    tool_timeout: Duration,
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionManager {
    #[must_use]
    pub fn new() -> Self {
        Self {
            sessions: DashMap::new(),
            aliases: DashMap::new(),
            open_timeout: DEFAULT_OPEN_TIMEOUT,
            tool_timeout: Duration::from_secs(30),
        }
    }

    #[must_use]
    pub fn with_open_timeout(open_timeout: Duration) -> Self {
        Self {
            sessions: DashMap::new(),
            aliases: DashMap::new(),
            open_timeout,
            tool_timeout: Duration::from_secs(30),
        }
    }

    /// Set the per-tool r2 command timeout.
    #[must_use]
    pub const fn with_tool_timeout(mut self, tool_timeout: Duration) -> Self {
        self.tool_timeout = tool_timeout;
        self
    }

    #[must_use]
    pub const fn open_timeout(&self) -> Duration {
        self.open_timeout
    }

    /// Open a binary in r2 or return the existing session outcome.
    ///
    /// # Errors
    ///
    /// Returns an error if the path cannot be canonicalized, r2 cannot be
    /// started, startup analysis fails, opening times out, or file metadata is
    /// not valid JSON.
    pub async fn open(&self, binary_path: impl AsRef<Path>) -> ToolResult<OpenOutcome> {
        let (session, canonical, was_new) = self.ensure_session(binary_path.as_ref()).await?;
        let info = session.cmdj("ij").await?;
        Ok(OpenOutcome {
            status: if was_new { "opened" } else { "already_open" },
            binary: canonical,
            info,
        })
    }

    /// Return an existing r2 session or open a new one for the binary.
    ///
    /// # Errors
    ///
    /// Returns an error if the path cannot be canonicalized, r2 cannot be
    /// started, startup analysis fails, or opening times out.
    pub async fn get_or_open(&self, binary_path: impl AsRef<Path>) -> ToolResult<Arc<Session>> {
        let (session, _, _) = self.ensure_session(binary_path.as_ref()).await?;
        Ok(session)
    }

    async fn ensure_session(&self, input: &Path) -> ToolResult<(Arc<Session>, PathBuf, bool)> {
        let canonical =
            fs::canonicalize(input).map_err(|e| ToolError::io(input.to_path_buf(), e))?;

        if let Some(existing) = self.lookup(&canonical) {
            self.remember_alias(input, &canonical);
            return Ok((existing, canonical, false));
        }

        let new_session = tokio::time::timeout(
            self.open_timeout,
            Session::spawn(canonical.clone(), self.tool_timeout),
        )
        .await
        .map_err(|_| {
            ToolError::backend(
                "r2",
                format!(
                    "session open timed out after {}s",
                    self.open_timeout.as_secs()
                ),
            )
        })??;
        let new_session_clone = new_session.clone();
        let raced = self.try_install(canonical.clone(), new_session);

        if raced {
            let existing = self.lookup(&canonical).ok_or_else(|| {
                ToolError::backend(
                    "r2",
                    format!("session raced and vanished: {}", canonical.display()),
                )
            })?;
            self.remember_alias(input, &canonical);
            return Ok((existing, canonical, false));
        }

        self.remember_alias(input, &canonical);
        Ok((new_session_clone, canonical, true))
    }

    /// Close a tracked r2 session for a binary path.
    ///
    /// # Errors
    ///
    /// Returns an error if the binary path cannot be resolved to a tracked session key.
    pub fn close(&self, binary_path: impl AsRef<Path>) -> ToolResult<CloseOutcome> {
        let input = binary_path.as_ref().to_path_buf();
        let key = self.resolve_close_key(&input);
        if let Some(session) = self.lookup(&key)
            && !session.shutdown()
        {
            tracing::warn!("session shutdown channel closed for {}", key.display());
        }
        let removed = self.sessions.remove(&key);
        if removed.is_some() {
            self.forget_aliases(&key);
        }
        let closed = removed.is_some();
        Ok(CloseOutcome {
            closed,
            binary: key,
        })
    }

    fn lookup(&self, canonical: &Path) -> Option<Arc<Session>> {
        self.sessions.get(canonical).map(|r| r.clone())
    }

    fn remember_alias(&self, input: &Path, canonical: &Path) {
        self.aliases
            .insert(input.to_path_buf(), canonical.to_path_buf());
    }

    fn resolve_close_key(&self, input: &Path) -> PathBuf {
        fs::canonicalize(input).unwrap_or_else(|_| {
            self.aliases
                .get(input)
                .map_or_else(|| input.to_path_buf(), |alias| alias.clone())
        })
    }

    fn forget_aliases(&self, canonical: &Path) {
        let aliases: Vec<PathBuf> = self
            .aliases
            .iter()
            .filter_map(|entry| {
                if entry.value().as_path() == canonical {
                    Some(entry.key().clone())
                } else {
                    None
                }
            })
            .collect();
        for alias in aliases {
            self.aliases.remove(&alias);
        }
    }

    fn try_install(&self, canonical: PathBuf, session: Arc<Session>) -> bool {
        match self.sessions.entry(canonical) {
            dashmap::Entry::Occupied(_) => true,
            dashmap::Entry::Vacant(slot) => {
                slot.insert(session);
                false
            }
        }
    }

    #[must_use]
    pub fn list(&self) -> Vec<PathBuf> {
        let mut paths: Vec<PathBuf> = self.sessions.iter().map(|r| r.key().clone()).collect();
        paths.sort();
        paths
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    pub fn get(&self, binary_path: impl AsRef<Path>) -> Option<Arc<Session>> {
        let raw = binary_path.as_ref();
        let key = fs::canonicalize(raw).ok()?;
        self.sessions.get(&key).map(|r| r.clone())
    }
}
