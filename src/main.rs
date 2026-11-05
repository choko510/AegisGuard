//! Thin CLI adapter over the `aegisguard` engine library: argument parsing
//! and printing only. Analyses live in the library so the GUI and the
//! service get the same typed results.
#[cfg(windows)]
use aegisguard::fimwatch;
#[cfg(not(feature = "yara"))]
use aegisguard::rules;
use aegisguard::Result;
use aegisguard::{c2, defender, engine, fim, jsonl, policy, report, rulepack, scan};
#[cfg(feature = "yara")]
use aegisguard::{store, yara, Error};
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use std::time::Duration;

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
    /// Limited file integrity monitoring of explicitly named paths (read-only).
    Fim {
        #[command(subcommand)]
        command: FimCommand,
    },
    /// Plan outbound blocks as a dry run and record approvals. Nothing is applied
    /// to Windows Firewall or any other OS setting.
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    /// Read-only browser-integrity checks (nothing is deleted or changed).
    Browser {
        #[command(subcommand)]
        command: BrowserCommand,
    },
    /// Read-only Microsoft Defender / ASR state audit (never changes settings).
    Defender {
        #[command(subcommand)]
        command: DefenderCommand,
    },
    /// Build a read-only local HTML report from saved command outputs.
    Report {
        #[command(subcommand)]
        command: ReportCommand,
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
        spool: Vec<PathBuf>,
    },
    /// Run the built-in correlation rules over a spool, offline. Findings are
    /// reasons to look, not verdicts; nothing is blocked or deleted.
    Correlate {
        /// One or more spools (e.g. Sysmon and Defender Operational).
        #[arg(long, default_value = "data/events/sysmon.jsonl")]
        spool: Vec<PathBuf>,
        #[command(flatten)]
        iocs: IocArgs,
    },
    /// Attribute IP and DNS IOC evidence to processes, with confidence and
    /// unknown visibility (DoH, VPN, disabled event types) stated.
    Iocs {
        /// One or more spools (e.g. Sysmon and Defender Operational).
        #[arg(long, default_value = "data/events/sysmon.jsonl")]
        spool: Vec<PathBuf>,
        #[command(flatten)]
        iocs: IocArgs,
    },
}

#[derive(clap::Args)]
struct IocArgs {
    /// C2 IP cache (only fresh indicators count as active).
    #[arg(long, default_value = "data/c2-cache.json")]
    c2_cache: PathBuf,
    /// User-owned IOC list: JSON array of {type: ip|domain, value, expires_at_unix}.
    #[arg(long)]
    local_iocs: Option<PathBuf>,
    /// User exceptions: same format plus a required `reason`; expired entries do not apply.
    #[arg(long)]
    allowlist: Option<PathBuf>,
}

impl IocArgs {
    fn load(&self) -> Result<aegisguard::ioc::IocSet> {
        let options = engine::IocOptions {
            c2_cache: self.c2_cache.clone(),
            local_iocs: self.local_iocs.clone(),
            allowlist: self.allowlist.clone(),
        };
        let (set, warnings) = options.load(now())?;
        for warning in warnings {
            eprintln!("warning: {warning}");
        }
        Ok(set)
    }
}

/// Print a value as one JSON line with sorted keys (the CLI's stable format).
fn print_json(value: &impl serde::Serialize) -> Result<()> {
    println!("{}", serde_json::to_string(&serde_json::to_value(value)?)?);
    Ok(())
}

#[derive(Subcommand)]
enum FimCommand {
    /// Record size, identity and SHA-256 of the named files or directories.
    Baseline {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        #[arg(long, default_value = "data/fim/baseline.json")]
        db: PathBuf,
    },
    /// Rescan and report created, modified, renamed, deleted and unreadable entries.
    Check {
        #[arg(long, default_value = "data/fim/baseline.json")]
        db: PathBuf,
    },
    /// Watch with Windows change notifications; every report comes from a rescan.
    Watch {
        #[arg(long, default_value = "data/fim/baseline.json")]
        db: PathBuf,
        #[arg(long, default_value_t = 60)]
        duration_secs: u64,
    },
}

#[derive(Subcommand)]
enum PolicyCommand {
    /// Turn attributed IOC findings into candidate rules and rejections (dry run).
    Plan {
        /// One or more spools (e.g. Sysmon and Defender Operational).
        #[arg(long, default_value = "data/events/sysmon.jsonl")]
        spool: Vec<PathBuf>,
        #[command(flatten)]
        iocs: IocArgs,
        #[arg(long, default_value_t = 24)]
        expiry_hours: u64,
        /// New file for the plan (never overwritten).
        #[arg(long)]
        out: PathBuf,
    },
    /// Record an administrator approval of a plan in an audit log (still a dry run).
    Approve {
        plan: PathBuf,
        #[arg(long)]
        approver: String,
        #[arg(long)]
        note: String,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value = "data/policy/audit.jsonl")]
        audit_log: PathBuf,
    },
}

#[derive(Subcommand)]
enum BrowserCommand {
    /// Look for the reported k2f traces (Chrome PlatformExperienceHelper DLL in a
    /// 64-hex folder + HKCU CLSID InprocServer32) for the current user.
    K2f {
        /// Use this folder instead of %LOCALAPPDATA% (e.g. a copied profile).
        #[arg(long)]
        local_app_data: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum DefenderCommand {
    /// Query Get-MpComputerStatus / Get-MpPreference and report states.
    Audit {
        /// Interpret a saved query result instead of querying this machine.
        #[arg(long)]
        from_json: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum ReportCommand {
    /// Write a static HTML file (no scripts, nothing uploaded, never overwritten).
    Html {
        /// Scan JSONL files (from `scan --output` or stdout).
        #[arg(long)]
        scan: Vec<PathBuf>,
        /// Output of `events correlate`.
        #[arg(long)]
        correlation: Option<PathBuf>,
        /// Output of `events iocs`.
        #[arg(long)]
        iocs: Option<PathBuf>,
        /// Output of `defender audit`.
        #[arg(long)]
        defender: Option<PathBuf>,
        /// Output of `c2 status`.
        #[arg(long)]
        c2_status: Option<PathBuf>,
        /// Output of `fim check`.
        #[arg(long)]
        fim: Option<PathBuf>,
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Subcommand)]
enum C2Command {
    /// Retrieve fresh IP indicators (HTTPS only); no blocking is performed.
    Update {
        #[arg(long, default_value = "data/c2-cache.json")]
        cache: PathBuf,
        /// Also fetch a source that is off by default (e.g. c2intel_verified,
        /// CC BY-NC-SA 4.0: non-commercial use only).
        #[arg(long = "include-source")]
        include_source: Vec<String>,
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
    engine::now()
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
    let output = engine::ManifestOutput::new(status, manifest, generation);
    println!(
        "{}",
        serde_json::to_value(output).expect("manifest output serializes")
    );
}

fn run_rules(command: RulesCommand) -> Result<()> {
    match command {
        RulesCommand::Check { dir } => check_rules(&dir),
        RulesCommand::Keygen { out } => print_json(&engine::keygen(&out)?),
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
    let health = engine::collect_events(channel, spool, checkpoint, max);
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

fn run_fim(command: FimCommand) -> Result<()> {
    match command {
        FimCommand::Baseline { paths, db } => {
            let baseline = fim::baseline(&paths, &db)?;
            println!(
                "{}",
                serde_json::json!({
                    "status": "baseline_recorded",
                    "entries": baseline.entries.len(),
                    "not_monitored": baseline.not_monitored,
                })
            );
        }
        FimCommand::Check { db } => {
            println!("{}", serde_json::to_string(&fim::check(&fim::load(&db)?))?);
        }
        #[cfg(windows)]
        FimCommand::Watch { db, duration_secs } => {
            fimwatch::watch(&fim::load(&db)?, Duration::from_secs(duration_secs))?;
        }
        #[cfg(not(windows))]
        FimCommand::Watch { .. } => {
            return Err(
                "change notifications are only implemented on Windows; use `fim check`".into(),
            );
        }
    }
    Ok(())
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
            command: EventsCommand::Iocs { spool, iocs },
        } => print_json(&engine::analyze_spools(&spool)?.attribute(&iocs.load()?))?,
        Commands::Events {
            command: EventsCommand::Correlate { spool, iocs },
        } => print_json(&engine::analyze_spools(&spool)?.correlate(&iocs.load()?))?,
        Commands::Events {
            command: EventsCommand::Processes { spool },
        } => print_json(&engine::analyze_spools(&spool)?.processes())?,
        Commands::Fim { command } => run_fim(command)?,
        Commands::Policy {
            command:
                PolicyCommand::Plan {
                    spool,
                    iocs,
                    expiry_hours,
                    out,
                },
        } => {
            let analysis = engine::analyze_spools(&spool)?;
            let output = engine::plan_blocks(&analysis, &iocs.load()?, expiry_hours, &out, now())?;
            print_json(&output)?;
        }
        Commands::Policy {
            command:
                PolicyCommand::Approve {
                    plan,
                    approver,
                    note,
                    out,
                    audit_log,
                },
        } => {
            let approved = policy::approve(&plan, &approver, &note, &out, &audit_log)?;
            println!(
                "{}",
                serde_json::json!({"status": "approved_not_applied", "plan_id": approved.plan_id, "out": out.display().to_string()})
            );
        }
        Commands::Browser {
            command: BrowserCommand::K2f { local_app_data },
        } => {
            let local =
                local_app_data.or_else(|| std::env::var_os("LOCALAPPDATA").map(PathBuf::from));
            #[cfg(windows)]
            let registry = aegisguard::browser::WindowsRegistry;
            #[cfg(not(windows))]
            let registry = aegisguard::browser::NoRegistry;
            let report = aegisguard::browser::check_k2f(local.as_deref(), &registry);
            print_json(&report)?;
        }
        Commands::Defender {
            command: DefenderCommand::Audit { from_json },
        } => {
            let raw = match from_json {
                Some(path) => serde_json::from_slice(&std::fs::read(path)?)?,
                None => defender::query()?,
            };
            let audit = defender::interpret(&raw);
            println!("{}", serde_json::to_string(&audit)?);
            if !audit.available {
                return Err("Defender state could not be read; see errors".into());
            }
        }
        Commands::Report {
            command:
                ReportCommand::Html {
                    scan,
                    correlation,
                    iocs,
                    defender,
                    c2_status,
                    fim,
                    out,
                },
        } => {
            let inputs = report::Inputs {
                scans: scan,
                correlation,
                iocs,
                defender,
                c2_status,
                fim,
            };
            report::write(&inputs, &out, now())?;
            println!(
                "{}",
                serde_json::json!({"status": "written", "out": out.display().to_string()})
            );
        }
        Commands::C2 { command } => match command {
            C2Command::Update {
                cache,
                include_source,
            } => c2::update(&cache, &include_source)?,
            C2Command::Check { ip, cache } => c2::check(&cache, ip)?,
            C2Command::Status { cache } => c2::status(&cache)?,
        },
    };
    Ok(())
}
