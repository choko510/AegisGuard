# Security Policy

AegisGuard is an experimental defensive utility, not a replacement for Microsoft Defender.

## Current attack surface

- Static file scanner is read-only and never executes scripts, DLLs, EXEs, interpreted code or decoded payloads.
- Deobfuscation has strict expansion, depth and layer limits. Oversized and malformed files are **not assessed**, rather than treated as safe.
- Files are opened without following a symlink/reparse point in the final path component (`O_NOFOLLOW` / `FILE_FLAG_OPEN_REPARSE_POINT`), with full sharing so other programs are never blocked. The opened handle's identity (volume serial + file index on Windows, device + inode on Unix) is recorded; on Windows and Linux the handle's resolved path must match the canonical parent of the requested path, so a directory swapped for a junction/symlink before open is reported (`path_identity_mismatch`). After reading, size/mtime of the handle and the path's identity are re-checked; a modified, replaced or deleted file is reported as `file_changed_during_scan` rather than attributed to the path. **Remaining limits**: an in-place rewrite that keeps the same size and modification time during the read is not detected, and other Unix platforms lack the resolved-path check.
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
