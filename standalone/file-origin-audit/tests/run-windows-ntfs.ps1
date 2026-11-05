#requires -Version 5.1
<#
.SYNOPSIS
  Opt-in end-to-end test of the standalone binary on a local NTFS volume.
.DESCRIPTION
  Only new harmless files in a unique temporary directory are modified.
  The CLI itself is read-only. -WithAcl temporarily denies file read access
  and restores the ACL in finally; do not use against existing files.
  Reparse tests require Windows Developer Mode or symlink privilege.
#>
[CmdletBinding()]
param(
    [switch]$WithAcl,
    [switch]$RequireReparse
)
$ErrorActionPreference = 'Stop'
$crate = Split-Path -Parent $PSScriptRoot
$binary = Join-Path $crate 'target\release\file-origin-audit.exe'
if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) {
    throw 'Build first: cargo build --release --manifest-path standalone/file-origin-audit/Cargo.toml'
}

$testDriveRoot = [System.IO.Path]::GetPathRoot([System.IO.Path]::GetTempPath())
if ($testDriveRoot.Length -ne 3 -or $testDriveRoot[1] -ne ':' -or [int]$testDriveRoot[2] -ne 92) {
    throw 'Test requires a local drive-letter temporary directory, not UNC/device path'
}
$testDriveLetter = $testDriveRoot.Substring(0, 1)
$testVolume = Get-Volume -DriveLetter $testDriveLetter -ErrorAction Stop
if ($testVolume.FileSystem -ne 'NTFS') {
    throw ('Test requires NTFS: found ' + $testVolume.FileSystem)
}
$root = Join-Path ([System.IO.Path]::GetTempPath()) ('file-origin-audit-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $root -ErrorAction Stop
$testFile = Join-Path $root 'harmless.txt'
$testSymlink = Join-Path $root 'harmless-link.txt'
$realParent = Join-Path $root 'real'
$linkedParent = Join-Path $root 'linked-parent'
$testSid = '*' + [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$aclAdded = $false
$createdFileLink = $false
$createdDirLink = $false

function Read-Audit([string]$file, [int]$expectedExit) {
    $output = & $binary inspect $file --format json
    $exit = $LASTEXITCODE
    if ($exit -ne $expectedExit) {
        throw "Wrong exit code: expected $expectedExit, got $exit"
    }
    if (@($output).Count -ne 1) {
        throw "Expected one JSON line"
    }
    return ($output | ConvertFrom-Json)
}

function Assert-Equals([object]$actual, [object]$expected, [string]$label) {
    if ($actual -ne $expected) {
        throw "$label expected '$expected', got '$actual'"
    }
}

try {
    Set-Content -LiteralPath $testFile -Value 'harmless synthetic data' -Encoding Ascii

    $without = Read-Audit $testFile 0
    Assert-Equals $without.status 'absent' 'ADS missing status'
    Assert-Equals $without.entries[0].motw_present $false 'MOTW missing'

    Set-Content -LiteralPath $testFile -Stream Zone.Identifier -Value @(
        '[ZoneTransfer]',
        'ZoneId=3',
        'HostUrl=https://example.invalid/?token=FAKE_NEVER_LOG'
    ) -Encoding Ascii
    $present = Read-Audit $testFile 0
    Assert-Equals $present.status 'present' 'ADS present status'
    Assert-Equals $present.entries[0].zone_id 3 'ZoneId'
    if (($present | ConvertTo-Json -Depth 10) -match 'FAKE_NEVER_LOG|example.invalid') {
        throw 'Sensitive origin URL escaped into JSON'
    }
    Write-Host 'PASS: NTFS ADS absent/present, ZoneId, URL redaction'

    try {
        $null = New-Item -ItemType SymbolicLink -Path $testSymlink -Target $testFile
        $createdFileLink = $true
        $result = Read-Audit $testSymlink 3
        Assert-Equals $result.status 'error' 'file symlink'
        Write-Host 'PASS: file symlink rejected'
    } catch {
        if ($createdFileLink -or $RequireReparse) { throw }
        Write-Warning 'SKIPPED file symlink test: symlink privilege/Developer Mode unavailable'
    }

    $null = New-Item -ItemType Directory -Path $realParent
    Set-Content -LiteralPath (Join-Path $realParent 'harmless.txt') -Value 'benign' -Encoding Ascii
    try {
        $null = New-Item -ItemType SymbolicLink -Path $linkedParent -Target $realParent
        $createdDirLink = $true
        $result = Read-Audit (Join-Path $linkedParent 'harmless.txt') 3
        Assert-Equals $result.status 'error' 'parent symlink'
        Write-Host 'PASS: parent directory symlink rejected'
    } catch {
        if ($createdDirLink -or $RequireReparse) { throw }
        Write-Warning 'SKIPPED directory symlink test: symlink privilege/Developer Mode unavailable'
    }

    if ($WithAcl) {
        & icacls.exe $testFile /deny "$($testSid):(R)" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Unable to add deny-read ACL to temporary file' }
        $aclAdded = $true
        $denied = Read-Audit $testFile 3
        Assert-Equals $denied.status 'permission_denied' 'ACL deny'
        Write-Host 'PASS: access denied returned, not a clean result'
    } else {
        Write-Warning 'SKIPPED actual DACL test: add -WithAcl for temporary-file ACL test'
    }

    Write-Host 'PASS: completed enabled synthetic NTFS checks'
} finally {
    if ($aclAdded) {
        & icacls.exe $testFile /remove:d $testSid | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "ACL rollback failed: only the temporary file at $testFile is affected"
        }
    }
    if ($createdFileLink) {
        Remove-Item -LiteralPath $testSymlink -Force -ErrorAction SilentlyContinue
    }
    if ($createdDirLink) {
        Remove-Item -LiteralPath $linkedParent -Force -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
