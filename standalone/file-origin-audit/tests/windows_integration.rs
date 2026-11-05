#![cfg(windows)]

// Harmless OS-backed tests. Require a local NTFS directory (the Windows runner
// normally provides this in %TEMP%). Only newly created synthetic files are used.
use file_origin_audit::inspect;
use std::ffi::OsString;
use std::fs;
use std::os::windows::fs::{symlink_dir, symlink_file};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let root = std::env::var_os("FILE_ORIGIN_AUDIT_TEST_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time available")
            .as_nanos();
        let path = root.join(format!(
            "file-origin-audit-windows-test-{}-{}",
            std::process::id(),
            nanos
        ));
        fs::create_dir(&path).expect("create temporary test directory");
        Self(path)
    }

    fn file(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn create_benign_file(path: &Path) {
    fs::write(path, b"harmless test contents\n").expect("create temporary benign file");
}

fn zone_stream_path(file: &Path) -> PathBuf {
    let mut name: OsString = file.as_os_str().to_os_string();
    name.push(":Zone.Identifier");
    PathBuf::from(name)
}

#[test]
fn ntfs_ads_absent_present_and_token_redaction() {
    let temp = Scratch::new();
    let file = temp.file("sample.txt");
    create_benign_file(&file);

    let missing = inspect(&file);
    assert_eq!(
        missing.status, "absent",
        "Requires a local NTFS test directory with readable named streams: {:?}",
        missing.warnings
    );
    assert_eq!(missing.motw_present, Some(false));
    assert!(missing.warnings.contains(&"absence_does_not_imply_safety"));

    let stream = zone_stream_path(&file);
    fs::write(
        &stream,
        b"[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://example.invalid/?token=FAKE_SECRET_NEVER_LOG\r\n",
    )
    .expect("create harmless NTFS Zone.Identifier stream");
    let result = inspect(&file);
    assert_eq!(
        result.status, "present",
        "Real NTFS ADS must be readable: {:?}",
        result.warnings
    );
    assert_eq!(result.zone_id, Some(3));
    assert_eq!(result.coverage, "complete");
    assert!(result.source_url_recorded);
    let json = result.to_json();
    assert!(!json.contains("FAKE_SECRET_NEVER_LOG"));
    assert!(!json.contains("example.invalid"));
    assert!(!json.contains(file.to_string_lossy().as_ref()));
}

#[test]
fn ntfs_target_reparse_point_is_rejected() {
    let temp = Scratch::new();
    let target = temp.file("target.txt");
    let link = temp.file("linked.txt");
    create_benign_file(&target);

    if let Err(error) = symlink_file(&target, &link) {
        if std::env::var_os("FILE_ORIGIN_AUDIT_REQUIRE_REPARSE").is_some() {
            panic!("Cannot create file symlink for mandatory test: {error}");
        }
        eprintln!("SKIPPED target symlink test: requires Windows symlink permission: {error}");
        return;
    }
    let report = inspect(&link);
    assert_eq!(report.status, "error");
    assert!(report.warnings.contains(&"reparse_point_rejected"));
    fs::remove_file(&link).expect("remove test symlink");
}

#[test]
fn ntfs_parent_directory_reparse_point_is_rejected() {
    let temp = Scratch::new();
    let real_dir = temp.file("real");
    let link_dir = temp.file("alias");
    fs::create_dir(&real_dir).expect("create real test directory");
    let file = real_dir.join("sample.txt");
    create_benign_file(&file);

    if let Err(error) = symlink_dir(&real_dir, &link_dir) {
        if std::env::var_os("FILE_ORIGIN_AUDIT_REQUIRE_REPARSE").is_some() {
            panic!("Cannot create directory symlink for mandatory test: {error}");
        }
        eprintln!("SKIPPED parent symlink test: requires Windows symlink permission: {error}");
        return;
    }
    let report = inspect(&link_dir.join("sample.txt"));
    assert_eq!(report.status, "error");
    assert!(report.warnings.contains(&"reparse_point_rejected"));
    fs::remove_dir(&link_dir).expect("remove directory symlink only");
}

#[test]
fn ntfs_access_denied_mock_is_not_a_clean_result() {
    // Actual DACL-denial is covered by the opt-in Windows PowerShell runner.
    // Never change persistent ACLs during a standard unit test run.
    let report = file_origin_audit::assess(
        file_origin_audit::Evidence::PermissionDenied,
        "windows_ads",
    );
    assert_eq!(report.status, "permission_denied");
    assert_eq!(report.coverage, "permission_denied");
    assert_eq!(report.motw_present, None);
}
