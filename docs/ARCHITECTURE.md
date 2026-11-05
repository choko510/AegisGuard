# AegisGuard: Rust-first architecture

## Design goals

Windows 11 target; compatibility with Microsoft Defender. Efficient service-based monitoring, explicit defensive policy enforcement, and offline-capable triage. **No private kernel driver** as an initial prerequisite.

## Crate/module boundaries

| Unit | Current (2026-11-05) | Target |
| --- | --- | --- |
| core / model | `aegisguard` library crate (`src/lib.rs`) with a thin CLI adapter (`src/main.rs`); typed engine operations (`engine`) and a versioned read-side contract (`api`: `ScanReportV2`, `SensorHealth`, `RuleStatus`, `CorrelationFinding`, `SourceFreshness`, `JobProgress`, bounded/cancellable JSONL reading that reports corrupt lines, newer schemas, unknown fields and truncation); JSONL schema v2 with independent completeness (`assessment`) and detection (`signal_level`) axes; handle-based file identity; time/size/file-count budgets | Split into a Cargo workspace (`aegis-core`, service, UI) once the service exists; score calibration |
| static script | Bounded literal deobfuscation and signatures; optional YARA-X (feature `yara`, no modules) over raw and decoded layers | Language-aware parsers (PowerShell AST/JS AST/Python AST), provenance graph |
| PE analysis | Bounded headers, W+X and section entropy, imports/exports, certificate table, overlay; Authenticode via `WinVerifyTrust` on the scanned handle (no UI, cache-only revocation) with catalog lookup | Packer evidence, signer reputation (never a safety verdict) |
| rules | Self-authored YARA rules with a provenance ledger, compile gate (warnings are errors), Ed25519-signed packs with replay protection and two-generation rollback | Rule QA corpus, reviewed third-party rules (after per-rule licensing) |
| IOC feeds | Source registry with license and default flag (Feodo default, C2Intel opt-in), two-generation cache, IocEvidence with expiry, user IOCs/allowlist with mandatory expiry | Domain/URL feeds with confirmed licensing, signed IOC packs |
| Windows sensor | Read-only Event Log collector (bookmark advanced only after a durable spool write, gaps reported), Sysmon ProcessGuid lifetimes incl. DLL loads, file creation and COM registry changes, limited FIM; SCM service (LocalService, observation only) with bounded continuous collection, incremental correlation over a bounded window, and a read-only authenticated Named Pipe IPC | Long-duration validation with Sysmon, LocalService/Event Log Readers deployment guidance |
| response | Dry-run outbound block planning and approval audit only; **no OS policy is modified** | Windows Firewall owned-rule backend (P3-03) after isolated-VM recovery evidence and explicit approval |
| Defender | Read-only `Get-MpComputerStatus` / `Get-MpPreference` audit | Defender Operational/ASR event correlation in reports |
| UI | egui/eframe desktop app following Fluent Design (non-privileged): file loading through the typed API, live service state over IPC, browser protection, network audit, tray and de-duplicated notifications; static HTML report kept | Accessibility review with screen readers, high-contrast themes |
| Browser integrity | k2f trace check, AG-B001..005 DLL/COM/load correlation, browser hijack timelines, credential-store reads from Security 4663 audit (no SACL changes), per-browser audit (forced extensions, HKCU COM servers in browser data) | Real-data false-positive evaluation with Sysmon |

### Event analysis (planned)

- Prefer Windows Event Log/Event API to read Sysmon EventID 1 (process), 3 (network, explicitly enabled), and 7 (image load, explicitly enabled).
- Join by ProcessGuid for process lifetime. Do not rely on PID alone due to reuse.
- Persist cursors/bookmarks and detect gaps, stream overflows, access failures, restart discontinuities.
- Do not enable extremely verbose DLL logging globally without filtered configurations.
- Correlate file hashes, script analysis results, event timestamps and network destinations without collecting document or browser contents by default.
- AMSI is an integration point, **not** a universal runtime monitor: Python has no automatic standard AMSI coverage. Windows Defender already consumes AMSI from supported hosts.

### Enforcement (planned)

- First deliver observation-only alerts.
- Build reversible, explicitly requested outbound Windows Firewall changes. Strictly own only AegisGuard-namespaced rules, never overwrite unrelated policy.
- Use Feodo as a possible blocking candidate; treat C2Intel as investigation-only by default.
- Enforce expiry, public-address validation, user allowlists, rule count caps, staged updates, startup recovery and audit logs.
- Use user-mode Windows facilities and avoid interfering with Defender's real-time protection.
- No arbitrary shell execution driven by samples, events or feed contents.

### Reliability work before release

1. Make scanner input handling resistant to reparse-point races and changes during read.
2. Introduce fuzzing, differential tests with safe and intentionally malformed PE/script fixtures.
3. Validate static detection false-positive rates using benign scripts and deterministic synthetic adversarial cases.
4. Add lockfile, SBOM, dependency vulnerability auditing, pinned action revisions and signed releases.
5. Benchmark CPU/memory on common Windows laptops; cap disk and network usage.
6. Test with Defender enabled, user/admin separation, and controlled rollback/failure injection.

The staged Rust API, browser integrity checks, egui dashboard, Windows service and safety gates are detailed in the [updated implementation roadmap](research/decisions/IMPLEMENTATION_ROADMAP.md#9-最新の到達目標と現状差分2026-11-05). Detection from events is observational; it does not block a write, module load or credential-file read before it occurs.

## Current scope

AegisGuard offers local static triage (optionally with YARA-X), manual IOC cache operations, read-only Windows event collection with offline correlation, limited FIM, a read-only Defender audit and a static HTML report. It does **not** offer real-time prevention, a resident service or any automatic blocking, and it never changes Defender, Windows Firewall or other OS security settings. Do not represent a heuristic or correlation match as malware certainty. Per-task status is in [IMPLEMENTATION_ROADMAP.md](research/decisions/IMPLEMENTATION_ROADMAP.md#8-実装状況2026-11-05).

