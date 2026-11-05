# AegisGuard: Rust-first architecture

## Design goals

Windows 11 target; compatibility with Microsoft Defender. Efficient service-based monitoring, explicit defensive policy enforcement, and offline-capable triage. **No private kernel driver** as an initial prerequisite.

## Crate/module boundaries

| Unit | Current (2026-11-05) | Target |
| --- | --- | --- |
| core / model | Rust CLI modules; JSONL schema v2 with independent completeness (`assessment`) and detection (`signal_level`) axes; handle-based file identity; time/size/file-count budgets | Extract reusable \`aegis-core\` library for reports, limits, rules, score calibration |
| static script | Bounded literal deobfuscation and signatures; optional YARA-X (feature `yara`, no modules) over raw and decoded layers | Language-aware parsers (PowerShell AST/JS AST/Python AST), provenance graph |
| PE analysis | Bounded headers, W+X and section entropy | Authenticode via Windows API, imports/exports, overlay semantics, packer evidence |
| rules | Self-authored YARA rules with a provenance ledger, compile gate (warnings are errors), Ed25519-signed packs with replay protection and two-generation rollback | Rule QA corpus, reviewed third-party rules (after per-rule licensing) |
| IOC feeds | Source registry with license and default flag (Feodo default, C2Intel opt-in), two-generation cache, IocEvidence with expiry, user IOCs/allowlist with mandatory expiry | Domain/URL feeds with confirmed licensing, signed IOC packs |
| Windows sensor | Read-only Event Log collector (bookmark advanced only after a durable spool write, gaps reported), Sysmon ProcessGuid lifetimes, offline correlation rules, limited FIM (rescan + ReadDirectoryChangesW) | Windows SCM service, bounded continuous Event Log collection, ProcessGuid correlation and narrow browser-related Sysmon 7/11/12-14 sources (P8) |
| response | Dry-run outbound block planning and approval audit only; **no OS policy is modified** | Windows Firewall owned-rule backend (P3-03) after isolated-VM recovery evidence and explicit approval |
| Defender | Read-only `Get-MpComputerStatus` / `Get-MpPreference` audit | Defender Operational/ASR event correlation in reports |
| UI | CLI JSONL and a static, script-free HTML report | egui/eframe desktop app (non-privileged), read-only offline view first; authenticated IPC to Windows service later |
| Browser integrity | No browser-specific DLL/COM detection; FIM intentionally does not read credential stores | Read-only DLL/CLSID IOC inspection, generic DLL/COM correlation, optional narrow audit metadata for credential-store reads (P6) |

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

