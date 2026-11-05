# Security Policy

AegisGuard is an experimental defensive utility, not a replacement for Microsoft Defender.

## Current attack surface

- Static file scanner is read-only and never executes scripts, DLLs, EXEs, interpreted code or decoded payloads.
- Deobfuscation has strict expansion, depth and layer limits. Oversized and malformed files are **not assessed**, rather than treated as safe.
- Symlink entries identified during initial metadata checks are skipped. **A path replacement/reparse-point race is still possible** between metadata inspection and open; a production Windows sensor must open handles with correct reparse-point policy and inspect identity consistently.
- C2 update performs HTTPS GET only to configured public sources. No local file contents or scans are uploaded.
- C2 feed strings are parsed as IP literals. Neither the feed contents nor the sample contents are interpolated into shell commands.
- There is no automatic firewall modification or process termination.
- JSONL reports may contain sensitive local file paths. Keep them under appropriate ACLs and avoid uploading them unreviewed.

## Known limitations

- No Authenticode certificate chain or revocation verification, AMSI, ETW, Sysmon, kernel driver or packet inspection is implemented yet.
- Static text signatures alone do not determine maliciousness; the source may be quoted, dead code or documentation.
- Sophisticated obfuscation, custom encryption, packed binaries and in-memory payloads are not generally decoded.
- IOC feeds can be outdated, incomplete or wrong; matches are investigative leads, not confirmed infections.
- There is no Windows-service hardening, signed updater, privilege separation or tamper protection.
- The project cannot prevent execution at the moment a file is opened. Windows Defender remains the primary enforcement layer.

## Reports

Please avoid placing live malware samples, credentials, access tokens or other secrets in public issues. Describe the triggering behavior, a harmless minimal reproduction, and the AegisGuard version instead.
