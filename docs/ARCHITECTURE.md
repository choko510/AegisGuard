# AegisGuard: Rust-first architecture

## Design goals

Windows 11 target; compatibility with Microsoft Defender. Efficient service-based monitoring, explicit defensive policy enforcement, and offline-capable triage. **No private kernel driver** as an initial prerequisite.

## Crate/module boundaries (planned evolution)

| Unit | Current | Target |
| --- | --- | --- |
| core / model | Rust CLI modules | Extract reusable \`aegis-core\` library for reports, limits, rules, score calibration |
| static script | Bounded literal deobfuscation and signatures | Language-aware parsers (PowerShell AST/JS AST/Python AST), provenance graph, YARA-X |
| PE analysis | Bounded headers, W+X and section entropy | Authenticode via Windows API, imports/exports, overlay semantics, packer evidence |
| IOC feeds | Feodo & validated C2Intel IP download/cache/check | Source provenance, expiry per source, allowlists, signed rules, domain + URL + IP:port |
| Windows sensor | Not implemented | Process creation, image loads, network event ingestion and correlation |
| response | Not implemented | Optional outbound firewall policy with dry-run, admin approval, rollback |
| UI | CLI JSONL | Desktop dashboard/client separate from privileged service |

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

## Current MVP scope

This branch offers local static triage and manual IOC cache operations. It does **not** offer real-time detection or automatic blocking yet. Do not represent a heuristic match as malware certainty.
