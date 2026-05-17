use anyhow::{Context, Result};
use clap::Parser;
use rbm_core::ServerConfig;
use rbm_server::RbmServer;

#[derive(Parser)]
#[command(
    name = "rbinr2",
    version,
    about = "MCP server for radare2-based binary analysis"
)]
struct Cli {
    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&cli.log_level)),
        )
        .init();

    let config = ServerConfig::from_env().context("failed to build server config from env")?;

    config
        .cache
        .ensure_all()
        .context("failed to prepare cache directories")?;

    let server = RbmServer::new(config);
    tracing::info!("rbinr2 MCP server starting on stdio");

    server
        .serve_stdio()
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(())
}
