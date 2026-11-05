mod budget;
mod c2;
// The collector only has a production caller on Windows (the Event Log source).
#[cfg_attr(not(windows), allow(dead_code))]
mod events;
mod fsafe;
mod jsonl;
mod model;
mod pe;
mod rulepack;
mod rules;
mod scan;
mod script;
mod store;
#[cfg(feature = "yara")]
mod yara;

use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
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
        #[arg(long, conflicts_with = "rule_store")]
        yara_rules: Option<PathBuf>,
        /// Use the signed rule pack installed in this store (see `rules install`).
        #[arg(long, requires = "trusted_key")]
        rule_store: Option<PathBuf>,
        /// Public key that rule packs must be signed with.
        #[arg(long)]
        trusted_key: Option<PathBuf>,
    },
    /// Validate, sign, install and roll back YARA rule sets.
    Rules {
        #[command(subcommand)]
        command: RulesCommand,
    },
    /// Read Windows event logs into a local spool (read-only; Windows only).
    Events {
        #[command(subcommand)]
        command: EventsCommand,
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
    /// Create an Ed25519 key pair (`<out>.key` secret, `<out>.pub` public).
    Keygen { out: PathBuf },
    /// Sign a rule directory (with its ledger.json) into a pack directory.
    Pack {
        dir: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        sequence: u64,
        #[arg(long, default_value_t = 30)]
        valid_days: u64,
        #[arg(long, default_value = "AegisGuard maintainers")]
        issuer: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify and install a signed pack; the previous pack is kept for rollback.
    Install {
        pack: PathBuf,
        #[arg(long)]
        trusted_key: PathBuf,
        #[arg(long, default_value = "data/rules")]
        store: PathBuf,
    },
    /// Return to the previously installed pack after re-verifying it.
    Rollback {
        #[arg(long)]
        trusted_key: PathBuf,
        #[arg(long, default_value = "data/rules")]
        store: PathBuf,
    },
    /// Show the installed pack and whether it still verifies.
    Status {
        #[arg(long)]
        trusted_key: PathBuf,
        #[arg(long, default_value = "data/rules")]
        store: PathBuf,
    },
}

#[derive(Subcommand)]
enum EventsCommand {
    /// Append new events of one channel to a JSONL spool. The cursor advances only
    /// after the spool is flushed; lost history is reported as a gap.
    Collect {
        #[arg(long, default_value = "Microsoft-Windows-Sysmon/Operational")]
        channel: String,
        #[arg(long, default_value = "data/events/sysmon.jsonl")]
        spool: PathBuf,
        #[arg(long, default_value = "data/events/sysmon.checkpoint.json")]
        checkpoint: PathBuf,
        #[arg(long, default_value_t = 100_000)]
        max_events: u64,
    },
    /// Rebuild Sysmon process lifetimes (keyed by ProcessGuid) from a spool, offline.
    Processes {
        #[arg(long, default_value = "data/events/sysmon.jsonl")]
        spool: PathBuf,
    },
    /// Run the built-in correlation rules over a spool, offline. Findings are
    /// reasons to look, not verdicts; nothing is blocked or deleted.
    Correlate {
        #[arg(long, default_value = "data/events/sysmon.jsonl")]
        spool: PathBuf,
        /// C2 cache for AG-C002 (only fresh indicators count).
        #[arg(long, default_value = "data/c2-cache.json")]
        c2_cache: PathBuf,
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

#[cfg(not(feature = "yara"))]
const NO_YARA: &str = "this build has no YARA support; rebuild with `--features yara`";

fn now() -> u64 {
    model::now_unix_ms() / 1000
}

/// Compile a verified pack's payload with the same gate as a rule directory.
#[cfg(feature = "yara")]
fn compile_payload(payload: &rulepack::Payload) -> std::result::Result<yara::RuleSet, Error> {
    let sources: Vec<_> = payload
        .files
        .iter()
        .map(|f| (f.name.clone(), f.source.clone()))
        .collect();
    yara::compile_sources(&sources).map_err(|problems| problems.join("\n").into())
}

#[cfg(feature = "yara")]
fn validate_payload(payload: &rulepack::Payload) -> Result<()> {
    compile_payload(payload).map(|_| ())
}

/// Without an engine a pack cannot be proven to compile, so it is refused.
#[cfg(not(feature = "yara"))]
fn validate_payload(_payload: &rulepack::Payload) -> Result<()> {
    Err(NO_YARA.into())
}

#[cfg(feature = "yara")]
fn check_rules(dir: &Path) -> Result<()> {
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
fn check_rules(dir: &Path) -> Result<()> {
    rules::read_ledger(dir)?;
    Err(NO_YARA.into())
}

fn print_manifest(status: &str, manifest: &rulepack::Manifest, generation: Option<&str>) {
    println!(
        "{}",
        serde_json::json!({
            "status": status,
            "issuer": manifest.issuer,
            "key_id": manifest.key_id,
            "sequence": manifest.sequence,
            "issued_at_unix": manifest.issued_at,
            "expires_at_unix": manifest.expires_at,
            "payload_sha256": manifest.payload_sha256,
            "generation": generation,
        })
    );
}

fn run_rules(command: RulesCommand) -> Result<()> {
    match command {
        RulesCommand::Check { dir } => check_rules(&dir),
        RulesCommand::Keygen { out } => {
            let mut seed = [0u8; 32];
            getrandom::getrandom(&mut seed).map_err(|e| format!("no OS randomness: {e}"))?;
            let key = ed25519_dalek::SigningKey::from_bytes(&seed);
            let secret = out.with_extension("key");
            let public = out.with_extension("pub");
            for path in [&secret, &public] {
                if path.exists() {
                    return Err(
                        format!("{} already exists; not overwriting", path.display()).into(),
                    );
                }
            }
            // Restrict the secret key file before any key material is written.
            let mut file = std::fs::File::create_new(&secret)?;
            store::restrict_to_owner(&secret)?;
            std::io::Write::write_all(&mut file, hex::encode(seed).as_bytes())?;
            std::fs::write(&public, hex::encode(key.verifying_key().as_bytes()))?;
            println!(
                "{}",
                serde_json::json!({
                    "secret_key": secret.display().to_string(),
                    "public_key": public.display().to_string(),
                    "key_id": rulepack::key_id(&key.verifying_key()),
                })
            );
            Ok(())
        }
        RulesCommand::Pack {
            dir,
            key,
            sequence,
            valid_days,
            issuer,
            out,
        } => {
            let key = rulepack::read_signing_key(&key)?;
            let options = rulepack::PackOptions {
                issuer: &issuer,
                sequence,
                issued_at: now(),
                valid_secs: valid_days.saturating_mul(24 * 3600),
            };
            rulepack::pack(&dir, &key, &options, &out)?;
            println!(
                "{}",
                serde_json::json!({"status": "packed", "out": out.display().to_string()})
            );
            Ok(())
        }
        RulesCommand::Install {
            pack,
            trusted_key,
            store,
        } => {
            let key = rulepack::read_verifying_key(&trusted_key)?;
            let manifest = rulepack::install(&pack, &store, &key, now(), &validate_payload)?;
            print_manifest("installed", &manifest, Some("current"));
            Ok(())
        }
        RulesCommand::Rollback { trusted_key, store } => {
            let key = rulepack::read_verifying_key(&trusted_key)?;
            let manifest = rulepack::rollback(&store, &key, now(), &validate_payload)?;
            print_manifest("rolled_back", &manifest, Some("current"));
            Ok(())
        }
        RulesCommand::Status { trusted_key, store } => {
            let key = rulepack::read_verifying_key(&trusted_key)?;
            let (pack, generation) = rulepack::load_active(&store, &key, now(), &validate_payload)?;
            print_manifest("valid", &pack.manifest, Some(generation.as_str()));
            Ok(())
        }
    }
}

/// The YARA rule set requested for a scan, if any. Fails closed: a requested
/// but unusable rule set stops the scan instead of silently skipping YARA.
#[cfg(feature = "yara")]
fn load_ruleset(
    yara_rules: Option<&Path>,
    rule_store: Option<&Path>,
    trusted_key: Option<&Path>,
) -> Result<Option<yara::RuleSet>> {
    if let Some(dir) = yara_rules {
        return yara::compile_dir(dir)
            .map(Some)
            .map_err(|problems| problems.join("\n").into());
    }
    let (Some(store), Some(key)) = (rule_store, trusted_key) else {
        return Ok(None);
    };
    let key = rulepack::read_verifying_key(key)?;
    // Signature, expiry and ledger are verified here; compiling happens once below.
    let (pack, generation) = rulepack::load_active(store, &key, now(), &|_| Ok(()))?;
    if generation != store::Generation::Current {
        eprintln!(
            "warning: using the {} rule pack generation; reinstall or roll back to repair",
            generation.as_str()
        );
    }
    compile_payload(&pack.payload).map(Some)
}

#[cfg(windows)]
fn collect_events(channel: &str, spool: PathBuf, checkpoint: PathBuf, max: u64) -> Result<()> {
    let mut source = events::winevt::WinEventSource::new(channel);
    let paths = events::collector::Paths { spool, checkpoint };
    let health = events::collector::collect(&mut source, &paths, max);
    println!("{}", serde_json::to_string(&health)?);
    match health.status {
        "ok" => Ok(()),
        status => Err(format!("event collection {status}; see the health record").into()),
    }
}

#[cfg(not(windows))]
fn collect_events(_: &str, _: PathBuf, _: PathBuf, _: u64) -> Result<()> {
    Err("event collection reads the Windows Event Log and is only available on Windows".into())
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
            rule_store,
            trusted_key,
        } => {
            let limits = scan::Limits {
                per_file: Duration::from_millis(file_time_limit_ms),
                max_files,
                max_total_bytes,
                max_duration: Duration::from_secs(max_duration_secs),
            };
            #[cfg(feature = "yara")]
            let ruleset = load_ruleset(
                yara_rules.as_deref(),
                rule_store.as_deref(),
                trusted_key.as_deref(),
            )?;
            #[cfg(not(feature = "yara"))]
            if yara_rules.is_some() || rule_store.is_some() || trusted_key.is_some() {
                return Err(NO_YARA.into());
            }
            #[cfg(feature = "yara")]
            let engines = scan::Engines {
                yara: ruleset.as_ref(),
            };
            #[cfg(not(feature = "yara"))]
            let engines = scan::Engines::default();
            let log = output
                .map(|p| jsonl::JsonlLog::open(&p, output_max_bytes, output_generations))
                .transpose()?;
            scan::run(&path, recursive, log, limits, engines)?
        }
        Commands::Rules { command } => run_rules(command)?,
        Commands::Events {
            command:
                EventsCommand::Collect {
                    channel,
                    spool,
                    checkpoint,
                    max_events,
                },
        } => collect_events(&channel, spool, checkpoint, max_events)?,
        Commands::Events {
            command: EventsCommand::Correlate { spool, c2_cache },
        } => {
            let (events, bad_lines) = events::process::read_spool(&spool)?;
            let table = events::process::ProcessTable::build(&events);
            let iocs = c2::IocLookup::load(&c2_cache)?;
            let result = events::correlate::correlate(&table, &|ip| iocs.fresh_sources(ip));
            println!(
                "{}",
                serde_json::json!({
                    "events": events.len(),
                    "bad_lines": bad_lines,
                    "duplicates": table.duplicates,
                    "anomalies": table.anomalies.len(),
                    "unobserved": table.unobserved(),
                    "correlation": result,
                })
            );
        }
        Commands::Events {
            command: EventsCommand::Processes { spool },
        } => {
            let (events, bad_lines) = events::process::read_spool(&spool)?;
            let table = events::process::ProcessTable::build(&events);
            println!(
                "{}",
                serde_json::json!({
                    "events": events.len(),
                    "bad_lines": bad_lines,
                    "unobserved": table.unobserved(),
                    "note": "Unobserved event types mean unknown activity, not absence of activity.",
                    "table": table,
                })
            );
        }
        Commands::C2 { command } => match command {
            C2Command::Update { cache } => c2::update(&cache)?,
            C2Command::Check { ip, cache } => c2::check(&cache, ip)?,
            C2Command::Status { cache } => c2::status(&cache)?,
        },
    };
    Ok(())
}
