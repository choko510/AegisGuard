//! Signed rule packs with replay protection and two-generation rollback.
//!
//! A pack is three files: `payload.json` (rule sources as text), `manifest.json`
//! (RuleManifest v1, binds the payload by SHA-256) and `manifest.sig` (hex Ed25519
//! signature over the exact manifest bytes). Installation verifies the signature
//! against a key the user explicitly trusts, the schema, validity window, payload
//! digest and size, a strictly increasing sequence number and finally that the
//! rules compile; only then is the pack stored as the new current generation.
//! Any failure keeps the previously installed pack. No key is built in.
use crate::rules::{self, LedgerEntry};
use crate::{store, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

pub const MANIFEST_SCHEMA: &str = "aegisguard-rule-manifest/1";
const MAX_MANIFEST_BYTES: u64 = 256 * 1024;
const MAX_PAYLOAD_BYTES: u64 = 8 * 1024 * 1024;
const MAX_INSTALLED_BYTES: u64 = 2 * MAX_PAYLOAD_BYTES;
/// Tolerated clock skew for `issued_at` in the future.
const MAX_CLOCK_SKEW_SECS: u64 = 300;
const MAX_VALIDITY_SECS: u64 = 400 * 24 * 3600;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema: String,
    pub issuer: String,
    pub key_id: String,
    pub sequence: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub payload_sha256: String,
    pub payload_bytes: u64,
    pub engine_requirement: String,
    pub origin_license_registry: Vec<LedgerEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PayloadFile {
    pub name: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Payload {
    pub files: Vec<PayloadFile>,
}

/// What is persisted per generation: the verbatim signed bytes, so the pack
/// can be re-verified whenever it is loaded.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Installed {
    manifest: String,
    signature: String,
    payload: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SequenceState {
    key_id: String,
    highest_sequence: u64,
}

pub struct VerifiedPack {
    pub manifest: Manifest,
    // Read by the YARA engine (feature `yara`) and the tests.
    #[cfg_attr(not(feature = "yara"), allow(dead_code))]
    pub payload: Payload,
}

pub fn key_id(key: &VerifyingKey) -> String {
    hex::encode(&Sha256::digest(key.as_bytes())[..8])
}

fn read_limited(path: &Path, max: u64) -> Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.len() > max {
        return Err(format!(
            "{} is not a regular file within the size limit",
            path.display()
        )
        .into());
    }
    Ok(fs::read(path)?)
}

fn decode_hex<const N: usize>(text: &str, what: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(text.trim()).map_err(|_| format!("{what} is not hex"))?;
    bytes
        .try_into()
        .map_err(|_| format!("{what} has the wrong length").into())
}

pub fn read_verifying_key(path: &Path) -> Result<VerifyingKey> {
    let text = String::from_utf8(read_limited(path, 1024)?)?;
    Ok(VerifyingKey::from_bytes(&decode_hex::<32>(
        &text,
        "public key",
    )?)?)
}

pub fn read_signing_key(path: &Path) -> Result<SigningKey> {
    let text = String::from_utf8(read_limited(path, 1024)?)?;
    Ok(SigningKey::from_bytes(&decode_hex::<32>(
        &text,
        "secret key",
    )?))
}

/// Verify a pack's bytes. `now` is unix seconds. `validate_rules` must compile
/// the payload (and is where a missing engine refuses the pack).
pub fn verify(
    manifest_bytes: &[u8],
    signature_hex: &str,
    payload_bytes: &[u8],
    key: &VerifyingKey,
    now: u64,
    validate_rules: &dyn Fn(&Payload) -> Result<()>,
) -> Result<VerifiedPack> {
    let signature = Signature::from_bytes(&decode_hex::<64>(signature_hex, "signature")?);
    key.verify(manifest_bytes, &signature)
        .map_err(|_| "manifest signature is invalid for the trusted key")?;
    let manifest: Manifest = serde_json::from_slice(manifest_bytes)?;
    if manifest.schema != MANIFEST_SCHEMA {
        return Err(format!("unsupported manifest schema {}", manifest.schema).into());
    }
    if manifest.key_id != key_id(key) {
        return Err("manifest key_id does not match the trusted key".into());
    }
    if manifest.issued_at > now.saturating_add(MAX_CLOCK_SKEW_SECS) {
        return Err("manifest is issued in the future".into());
    }
    if manifest.expires_at <= now {
        return Err("manifest has expired".into());
    }
    if manifest.expires_at <= manifest.issued_at
        || manifest.expires_at - manifest.issued_at > MAX_VALIDITY_SECS
    {
        return Err("manifest validity window is invalid".into());
    }
    if manifest.payload_bytes > MAX_PAYLOAD_BYTES
        || payload_bytes.len() as u64 != manifest.payload_bytes
    {
        return Err("payload length does not match the manifest".into());
    }
    if hex::encode(Sha256::digest(payload_bytes)) != manifest.payload_sha256 {
        return Err("payload digest does not match the manifest".into());
    }
    let payload: Payload = serde_json::from_slice(payload_bytes)?;
    if payload.files.is_empty() {
        return Err("payload contains no rule files".into());
    }
    for file in &payload.files {
        let safe = !file.name.is_empty()
            && file
                .name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
            && !file.name.starts_with('.')
            && (file.name.ends_with(".yar") || file.name.ends_with(".yara"));
        if !safe {
            return Err(format!("unsafe rule file name {:?}", file.name).into());
        }
        if !manifest
            .origin_license_registry
            .iter()
            .any(|entry| entry.file == file.name)
        {
            return Err(format!("{} has no origin/license ledger entry", file.name).into());
        }
    }
    validate_rules(&payload)?;
    Ok(VerifiedPack { manifest, payload })
}

pub struct PackOptions<'a> {
    pub issuer: &'a str,
    pub sequence: u64,
    pub issued_at: u64,
    pub valid_secs: u64,
}

/// Build a signed pack from a rule directory and its `ledger.json`. Used by maintainers.
pub fn pack(rule_dir: &Path, key: &SigningKey, options: &PackOptions, out: &Path) -> Result<()> {
    let ledger = rules::read_ledger(rule_dir)?;
    let names = rules::rule_files(rule_dir)?;
    let mut files = Vec::new();
    for path in names {
        files.push(PayloadFile {
            name: path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into(),
            source: String::from_utf8(read_limited(&path, MAX_PAYLOAD_BYTES)?)?,
        });
    }
    let payload = serde_json::to_vec_pretty(&Payload { files })?;
    let manifest = Manifest {
        schema: MANIFEST_SCHEMA.into(),
        issuer: options.issuer.into(),
        key_id: key_id(&key.verifying_key()),
        sequence: options.sequence,
        issued_at: options.issued_at,
        expires_at: options.issued_at.saturating_add(options.valid_secs),
        payload_sha256: hex::encode(Sha256::digest(&payload)),
        payload_bytes: payload.len() as u64,
        engine_requirement: "yara-x>=1.22,<2".into(),
        origin_license_registry: ledger,
    };
    let manifest = serde_json::to_vec_pretty(&manifest)?;
    let signature = hex::encode(key.sign(&manifest).to_bytes());
    fs::create_dir_all(out)?;
    fs::write(out.join("payload.json"), payload)?;
    fs::write(out.join("manifest.json"), &manifest)?;
    fs::write(out.join("manifest.sig"), signature)?;
    Ok(())
}

fn active_path(store_dir: &Path) -> std::path::PathBuf {
    store_dir.join("rulepack.json")
}

fn sequence_path(store_dir: &Path) -> std::path::PathBuf {
    store_dir.join("sequence.json")
}

fn parse_installed(bytes: &[u8]) -> Result<Installed> {
    Ok(serde_json::from_slice(bytes)?)
}

fn verify_installed(
    installed: &Installed,
    key: &VerifyingKey,
    now: u64,
    validate_rules: &dyn Fn(&Payload) -> Result<()>,
) -> Result<VerifiedPack> {
    verify(
        installed.manifest.as_bytes(),
        &installed.signature,
        installed.payload.as_bytes(),
        key,
        now,
        validate_rules,
    )
}

fn highest_sequence(store_dir: &Path, key: &VerifyingKey) -> Result<u64> {
    let parse = |b: &[u8]| -> Result<SequenceState> { Ok(serde_json::from_slice(b)?) };
    Ok(match store::load(&sequence_path(store_dir), 4096, parse)? {
        Some((state, _)) if state.key_id == key_id(key) => state.highest_sequence,
        _ => 0,
    })
}

/// Install a pack directory produced by [`pack`]. Returns the new manifest.
pub fn install(
    pack_dir: &Path,
    store_dir: &Path,
    key: &VerifyingKey,
    now: u64,
    validate_rules: &dyn Fn(&Payload) -> Result<()>,
) -> Result<Manifest> {
    let manifest = String::from_utf8(read_limited(
        &pack_dir.join("manifest.json"),
        MAX_MANIFEST_BYTES,
    )?)?;
    let signature = String::from_utf8(read_limited(&pack_dir.join("manifest.sig"), 1024)?)?;
    let payload = String::from_utf8(read_limited(
        &pack_dir.join("payload.json"),
        MAX_PAYLOAD_BYTES,
    )?)?;
    let installed = Installed {
        manifest,
        signature: signature.trim().to_owned(),
        payload,
    };
    let verified = verify_installed(&installed, key, now, validate_rules)?;
    let highest = highest_sequence(store_dir, key)?;
    if verified.manifest.sequence <= highest {
        return Err(format!(
            "sequence {} is not newer than the installed {highest}; replay rejected",
            verified.manifest.sequence
        )
        .into());
    }
    fs::create_dir_all(store_dir)?;
    let bytes = serde_json::to_vec(&installed)?;
    store::store(&active_path(store_dir), &bytes, |b| {
        parse_installed(b).map(|_| ())
    })?;
    // Record the sequence only after the pack itself is durable.
    let state = serde_json::to_vec(&SequenceState {
        key_id: key_id(key),
        highest_sequence: verified.manifest.sequence,
    })?;
    store::store(&sequence_path(store_dir), &state, |b| {
        serde_json::from_slice::<SequenceState>(b)
            .map(|_| ())
            .map_err(Into::into)
    })?;
    Ok(verified.manifest)
}

/// Load and re-verify the installed pack (newest valid generation).
pub fn load_active(
    store_dir: &Path,
    key: &VerifyingKey,
    now: u64,
    validate_rules: &dyn Fn(&Payload) -> Result<()>,
) -> Result<(VerifiedPack, store::Generation)> {
    let Some((installed, generation)) = store::load(
        &active_path(store_dir),
        MAX_INSTALLED_BYTES,
        parse_installed,
    )?
    else {
        return Err("no rule pack is installed".into());
    };
    Ok((
        verify_installed(&installed, key, now, validate_rules)?,
        generation,
    ))
}

/// Explicitly return to the previous generation after re-verifying it.
/// The highest seen sequence is kept, so the rolled-back-from pack can be
/// reinstalled only with a newer sequence.
pub fn rollback(
    store_dir: &Path,
    key: &VerifyingKey,
    now: u64,
    validate_rules: &dyn Fn(&Payload) -> Result<()>,
) -> Result<Manifest> {
    let previous = store::previous_path(&active_path(store_dir));
    let bytes = read_limited(&previous, MAX_INSTALLED_BYTES)?;
    let installed = parse_installed(&bytes)?;
    let verified = verify_installed(&installed, key, now, validate_rules)?;
    store::store(&active_path(store_dir), &bytes, |b| {
        parse_installed(b).map(|_| ())
    })?;
    Ok(verified.manifest)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULE: &str = "rule AG_Test { meta: id = \"AG-T1\" version = 1 severity = 1 origin = \"self-authored\" condition: false }\n";

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("aegisguard-pack-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn accept(_: &Payload) -> Result<()> {
        Ok(())
    }

    fn ledger() -> Vec<LedgerEntry> {
        vec![LedgerEntry {
            file: "a.yar".into(),
            origin: "self-authored".into(),
            license: "test".into(),
        }]
    }

    fn make_pack(
        dir: &Path,
        signer: &SigningKey,
        sequence: u64,
        issued_at: u64,
    ) -> std::path::PathBuf {
        let rule_dir = dir.join(format!("rules-{sequence}"));
        fs::create_dir_all(&rule_dir).unwrap();
        fs::write(rule_dir.join("a.yar"), format!("{RULE}// seq {sequence}\n")).unwrap();
        fs::write(
            rule_dir.join(rules::LEDGER_FILE),
            serde_json::to_vec(&ledger()).unwrap(),
        )
        .unwrap();
        let out = dir.join(format!("pack-{sequence}"));
        let options = PackOptions {
            issuer: "test",
            sequence,
            issued_at,
            valid_secs: 3600,
        };
        pack(&rule_dir, signer, &options, &out).unwrap();
        out
    }

    #[test]
    fn valid_pack_installs_and_reloads() {
        let dir = temp_dir("valid");
        let signer = key(1);
        let pack_dir = make_pack(&dir, &signer, 1, 1_000);
        let store_dir = dir.join("store");
        let manifest = install(
            &pack_dir,
            &store_dir,
            &signer.verifying_key(),
            1_100,
            &accept,
        )
        .unwrap();
        assert_eq!(manifest.sequence, 1);
        let (loaded, generation) =
            load_active(&store_dir, &signer.verifying_key(), 1_100, &accept).unwrap();
        assert_eq!(generation, store::Generation::Current);
        assert!(loaded.payload.files[0].source.contains("AG_Test"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn tampering_wrong_key_expiry_and_replay_are_rejected_and_keep_old_pack() {
        let dir = temp_dir("reject");
        let signer = key(1);
        let trusted = signer.verifying_key();
        let store_dir = dir.join("store");
        let first = make_pack(&dir, &signer, 5, 1_000);
        install(&first, &store_dir, &trusted, 1_100, &accept).unwrap();

        // Tampered payload.
        let tampered = make_pack(&dir, &signer, 6, 1_000);
        fs::write(tampered.join("payload.json"), b"{\"files\":[]}").unwrap();
        assert!(install(&tampered, &store_dir, &trusted, 1_100, &accept).is_err());
        // Tampered manifest (signature no longer matches).
        let edited = make_pack(&dir, &signer, 7, 1_000);
        let text = fs::read_to_string(edited.join("manifest.json")).unwrap();
        fs::write(
            edited.join("manifest.json"),
            text.replace("\"sequence\": 7", "\"sequence\": 70"),
        )
        .unwrap();
        assert!(install(&edited, &store_dir, &trusted, 1_100, &accept).is_err());
        // Signed by an untrusted key.
        let foreign = make_pack(&dir, &key(2), 8, 1_000);
        assert!(install(&foreign, &store_dir, &trusted, 1_100, &accept).is_err());
        // Expired and future-dated.
        let old = make_pack(&dir, &signer, 9, 1_000);
        assert!(install(&old, &store_dir, &trusted, 1_000 + 3_600, &accept).is_err());
        let future = make_pack(&dir, &signer, 10, 50_000);
        assert!(install(&future, &store_dir, &trusted, 1_100, &accept).is_err());
        // Replay of an older or equal sequence.
        let replay = make_pack(&dir, &signer, 5, 1_050);
        assert!(install(&replay, &store_dir, &trusted, 1_100, &accept).is_err());
        // Rules that fail validation (e.g. compile errors).
        let broken = make_pack(&dir, &signer, 11, 1_000);
        let reject = |_: &Payload| -> Result<()> { Err("does not compile".into()) };
        assert!(install(&broken, &store_dir, &trusted, 1_100, &reject).is_err());

        let (active, _) = load_active(&store_dir, &trusted, 1_100, &accept).unwrap();
        assert_eq!(active.manifest.sequence, 5);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rollback_restores_previous_verified_generation_without_lowering_sequence() {
        let dir = temp_dir("rollback");
        let signer = key(3);
        let trusted = signer.verifying_key();
        let store_dir = dir.join("store");
        install(
            &make_pack(&dir, &signer, 1, 1_000),
            &store_dir,
            &trusted,
            1_100,
            &accept,
        )
        .unwrap();
        install(
            &make_pack(&dir, &signer, 2, 1_000),
            &store_dir,
            &trusted,
            1_100,
            &accept,
        )
        .unwrap();
        let restored = rollback(&store_dir, &trusted, 1_100, &accept).unwrap();
        assert_eq!(restored.sequence, 1);
        let (active, _) = load_active(&store_dir, &trusted, 1_100, &accept).unwrap();
        assert_eq!(active.manifest.sequence, 1);
        // Re-installing sequence 2 is a replay now; only a newer pack is accepted.
        assert!(install(
            &make_pack(&dir, &signer, 2, 1_010),
            &store_dir,
            &trusted,
            1_100,
            &accept
        )
        .is_err());
        install(
            &make_pack(&dir, &signer, 3, 1_000),
            &store_dir,
            &trusted,
            1_100,
            &accept,
        )
        .unwrap();
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn torn_active_file_falls_back_to_previous_generation() {
        let dir = temp_dir("torn");
        let signer = key(4);
        let trusted = signer.verifying_key();
        let store_dir = dir.join("store");
        install(
            &make_pack(&dir, &signer, 1, 1_000),
            &store_dir,
            &trusted,
            1_100,
            &accept,
        )
        .unwrap();
        install(
            &make_pack(&dir, &signer, 2, 1_000),
            &store_dir,
            &trusted,
            1_100,
            &accept,
        )
        .unwrap();
        let active = active_path(&store_dir);
        let bytes = fs::read(&active).unwrap();
        fs::write(&active, &bytes[..bytes.len() / 3]).unwrap();
        let (pack, generation) = load_active(&store_dir, &trusted, 1_100, &accept).unwrap();
        assert_eq!(generation, store::Generation::Previous);
        assert_eq!(pack.manifest.sequence, 1);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn unsafe_names_and_missing_ledger_are_rejected() {
        let dir = temp_dir("names");
        let signer = key(5);
        for (name, with_ledger) in [("../evil.yar", true), ("ok.yar", false), ("x.exe", true)] {
            let payload = serde_json::to_vec(&Payload {
                files: vec![PayloadFile {
                    name: name.into(),
                    source: RULE.into(),
                }],
            })
            .unwrap();
            let manifest = serde_json::to_vec(&Manifest {
                schema: MANIFEST_SCHEMA.into(),
                issuer: "t".into(),
                key_id: key_id(&signer.verifying_key()),
                sequence: 1,
                issued_at: 1_000,
                expires_at: 2_000,
                payload_sha256: hex::encode(Sha256::digest(&payload)),
                payload_bytes: payload.len() as u64,
                engine_requirement: "yara-x".into(),
                origin_license_registry: if with_ledger {
                    vec![LedgerEntry {
                        file: name.into(),
                        origin: "o".into(),
                        license: "l".into(),
                    }]
                } else {
                    Vec::new()
                },
            })
            .unwrap();
            let sig = hex::encode(signer.sign(&manifest).to_bytes());
            assert!(verify(
                &manifest,
                &sig,
                &payload,
                &signer.verifying_key(),
                1_100,
                &accept
            )
            .is_err());
        }
        fs::remove_dir_all(dir).unwrap();
    }
}
