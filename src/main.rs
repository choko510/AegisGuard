mod budget;
mod c2;
mod fsafe;
mod jsonl;
mod model;
mod pe;
mod scan;
mod script;
mod store;

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::time::Duration;

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
        /// Rotate the --output file once it would exceed this size.
        #[arg(long, default_value_t = 64 * 1024 * 1024)]
        output_max_bytes: u64,
        /// Rotated generations to keep (scan.jsonl.1 ...); 0 stops at the size limit.
        #[arg(long, default_value_t = 5)]
        output_generations: u32,
        /// Per-file analysis time budget; reaching it marks the file incomplete.
        #[arg(long, default_value_t = 10_000)]
        file_time_limit_ms: u64,
        /// Stop after this many scan targets (an explicit scan_stopped record is written).
        #[arg(long, default_value_t = 200_000)]
        max_files: u64,
        /// Stop after reading this many bytes in total.
        #[arg(long, default_value_t = 32 * 1024 * 1024 * 1024)]
        max_total_bytes: u64,
        /// Stop after this many seconds of wall-clock time.
        #[arg(long, default_value_t = 4 * 3600)]
        max_duration_secs: u64,
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
            output_max_bytes,
            output_generations,
            file_time_limit_ms,
            max_files,
            max_total_bytes,
            max_duration_secs,
        } => {
            let limits = scan::Limits {
                per_file: Duration::from_millis(file_time_limit_ms),
                max_files,
                max_total_bytes,
                max_duration: Duration::from_secs(max_duration_secs),
            };
            let log = output
                .map(|p| jsonl::JsonlLog::open(&p, output_max_bytes, output_generations))
                .transpose()?;
            scan::run(&path, recursive, log, limits)?
        }
        Commands::C2 { command } => match command {
            C2Command::Update { cache } => c2::update(&cache)?,
            C2Command::Check { ip, cache } => c2::check(&cache, ip)?,
            C2Command::Status { cache } => c2::status(&cache)?,
        },
    };
    Ok(())
}
