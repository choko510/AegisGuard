mod c2;
mod fsafe;
mod model;
mod pe;
mod scan;
mod script;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

type Error = Box<dyn std::error::Error + Send + Sync>;
type Result<T> = std::result::Result<T, Error>;

#[derive(Parser)]
#[command(
    author,
    version,
    about = "AegisGuard: read-only file triage and defensive C2 indicator lookup"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Inspect local files without executing them; emits JSONL to stdout.
    Scan {
        path: PathBuf,
        #[arg(long)]
        recursive: bool,
        /// Append reports to a local JSONL file; never uploads samples.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Manage a locally cached list of public C2 indicators.
    C2 {
        #[command(subcommand)]
        command: C2Command,
    },
}

#[derive(Subcommand)]
enum C2Command {
    /// Retrieve fresh IP indicators (HTTPS only); no blocking is performed.
    Update {
        #[arg(long, default_value = "data/c2-cache.json")]
        cache: PathBuf,
    },
    /// Check an IP address against local cached indicators.
    Check {
        ip: std::net::IpAddr,
        #[arg(long, default_value = "data/c2-cache.json")]
        cache: PathBuf,
    },
    /// Summarize local indicator cache freshness and counts.
    Status {
        #[arg(long, default_value = "data/c2-cache.json")]
        cache: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Scan {
            path,
            recursive,
            output,
        } => scan::run(&path, recursive, output.as_deref())?,
        Commands::C2 { command } => match command {
            C2Command::Update { cache } => c2::update(&cache)?,
            C2Command::Check { ip, cache } => c2::check(&cache, ip)?,
            C2Command::Status { cache } => c2::status(&cache)?,
        },
    };
    Ok(())
}
