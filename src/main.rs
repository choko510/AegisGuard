mod budget;
mod c2;
mod fsafe;
mod jsonl;
mod model;
mod pe;
mod rules;
mod scan;
mod script;
mod store;
#[cfg(feature = "yara")]
mod yara;

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
        /// Also scan raw and decoded layers with the YARA rules in this directory
        /// (audit only; needs a build with `--features yara`).
        #[arg(long)]
        yara_rules: Option<PathBuf>,
    },
    /// Validate YARA rule sources: ledger, compile errors and warnings.
    Rules {
        #[command(subcommand)]
        command: RulesCommand,
    },
    /// Manage a locally cached list of public C2 indicators.
    C2 {
        #[command(subcommand)]
        command: C2Command,
    },
}

#[derive(Subcommand)]
enum RulesCommand {
    /// Compile a rule directory with the same gate used by `scan --yara-rules`.
    Check { dir: PathBuf },
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

#[cfg(not(feature = "yara"))]
const NO_YARA: &str = "this build has no YARA support; rebuild with `--features yara`";

#[cfg(feature = "yara")]
fn check_rules(dir: &std::path::Path) -> Result<()> {
    match yara::compile_dir(dir) {
        Ok(set) => {
            println!(
                "{}",
                serde_json::json!({"status": "ok", "ruleset_sha256": set.sha256, "rule_ids": set.rule_ids})
            );
            Ok(())
        }
        Err(problems) => {
            println!(
                "{}",
                serde_json::json!({"status": "rejected", "problems": problems})
            );
            Err("rule set rejected".into())
        }
    }
}

#[cfg(not(feature = "yara"))]
fn check_rules(dir: &std::path::Path) -> Result<()> {
    rules::read_ledger(dir)?;
    Err(NO_YARA.into())
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
            yara_rules,
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
            #[cfg(feature = "yara")]
            let ruleset = yara_rules
                .as_deref()
                .map(|dir| {
                    yara::compile_dir(dir).map_err(|problems| {
                        problems.join(
                            "
",
                        )
                    })
                })
                .transpose()?;
            #[cfg(not(feature = "yara"))]
            if yara_rules.is_some() {
                return Err(NO_YARA.into());
            }
            #[cfg(feature = "yara")]
            let engines = scan::Engines {
                yara: ruleset.as_ref(),
            };
            #[cfg(not(feature = "yara"))]
            let engines = scan::Engines::default();
            scan::run(&path, recursive, log, limits, engines)?
        }
        Commands::Rules {
            command: RulesCommand::Check { dir },
        } => check_rules(&dir)?,
        Commands::C2 { command } => match command {
            C2Command::Update { cache } => c2::update(&cache)?,
            C2Command::Check { ip, cache } => c2::check(&cache, ip)?,
            C2Command::Status { cache } => c2::status(&cache)?,
        },
    };
    Ok(())
}
