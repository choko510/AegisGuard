# Security Policy

AegisGuard is an experimental defensive utility, not a replacement for Microsoft Defender.

## Current attack surface

- Static file scanner is read-only and never executes scripts, DLLs, EXEs, interpreted code or decoded payloads.
- Deobfuscation has strict expansion, depth and layer limits. Oversized and malformed files are **not assessed**, rather than treated as safe.
- Files are opened without following a symlink/reparse point in the final path component (`O_NOFOLLOW` / `FILE_FLAG_OPEN_REPARSE_POINT`), with full sharing so other programs are never blocked. The opened handle's identity (volume serial + file index on Windows, device + inode on Unix) is recorded; on Windows and Linux the handle's resolved path must match the canonical parent of the requested path, so a directory swapped for a junction/symlink before open is reported (`path_identity_mismatch`). After reading, size/mtime of the handle and the path's identity are re-checked; a modified, replaced or deleted file is reported as `file_changed_during_scan` rather than attributed to the path. **Remaining limits**: an in-place rewrite that keeps the same size and modification time during the read is not detected, and other Unix platforms lack the resolved-path check.
- C2 update performs HTTPS GET only to configured public sources. No local file contents or scans are uploaded.
- C2 feed strings are parsed as IP literals. Neither the feed contents nor the sample contents are interpolated into shell commands.
- There is no automatic firewall modification or process termination.
- Optional YARA-X scanning compiles trusted text rules in-process; serialized rule binaries are never loaded, `include` is disabled, no YARA module is compiled in, and any compile error or warning rejects the whole rule set. Rule packs must carry a valid Ed25519 signature from a key the user explicitly trusts (none is built in), a strictly increasing sequence number and an unexpired validity window; secret key files are created owner-only, and protecting them is the key holder's responsibility.
- `events collect` only reads Windows event channels (no subscription, audit-policy, channel or Sysmon configuration changes). The spool and checkpoint contain process images, destinations and DNS names; command lines are stored only as SHA-256, user and host names are not stored, and new files are owner-only.
- `defender audit` runs the system PowerShell (absolute path) with a fixed script that calls only `Get-MpComputerStatus`, `Get-MpPreference` and `Test-Path` on the Defender policy key. No sample, path or user input is interpolated, and nothing is set, added or removed. Exclusion paths are counted, not printed.
- `fim` hashes only the paths the user names, never follows links, and never opens files named like browser credential/cookie stores or registry hives.
- `policy` produces dry-run plans and appends approvals to an audit log; the build contains no code that modifies Windows Firewall, WFP or other OS policy.
- `report html` writes a static page with a script-forbidding Content-Security-Policy and escapes every value.
- JSONL reports may contain sensitive local file paths. AegisGuard creates report and cache files readable by the owner only (Unix 0600; Windows protected DACL for owner, SYSTEM and Administrators). Files that already existed keep their ACLs. Avoid uploading reports unreviewed.

## Known limitations

- No Authenticode certificate chain or revocation verification, AMSI, ETW, kernel driver or packet inspection is implemented. Sysmon events are read only if the user installed and configured Sysmon; event types that were not observed are reported as unknown, not as absence of activity.
- Static text signatures alone do not determine maliciousness; the source may be quoted, dead code or documentation.
- Sophisticated obfuscation, custom encryption, packed binaries and in-memory payloads are not generally decoded.
- IOC feeds can be outdated, incomplete or wrong; matches are investigative leads, not confirmed infections.
- There is no resident Windows service, privilege separation or tamper protection. Rule packs are signed; the C2 IP cache is not (it is fetched over HTTPS from the configured sources).
- The project cannot prevent execution at the moment a file is opened. Windows Defender remains the primary enforcement layer.

## Reports

Please avoid placing live malware samples, credentials, access tokens or other secrets in public issues. Describe the triggering behavior, a harmless minimal reproduction, and the AegisGuard version instead.
