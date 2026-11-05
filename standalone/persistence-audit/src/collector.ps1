# Read-only Windows PowerShell 5.1 inventory. Emits only sanitized NDJSON.
# $Max and $EnableWmi are fixed, validated values prepended by Rust.
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$script:Count = 0
$script:LimitHit = $false
$script:IdKey = $null

# Stable identifiers are OPT-IN: an operator-provided random 32-byte key.
# Never put registry names, task names, filenames, WQL or command arguments on stdout.
try {
    $decoded = [Convert]::FromBase64String($env:AEGISGUARD_PERSISTENCE_ID_KEY_B64)
    if ($decoded.Length -eq 32) { $script:IdKey = $decoded }
} catch { $script:IdKey = $null }

function Get-EntryId([string]$section, [AllowNull()][string]$identity) {
    if ($null -eq $script:IdKey -or $null -eq $identity -or $identity.Length -gt 4096) {
        return $null
    }
    $text = $section + [char]0 + $identity.Normalize([Text.NormalizationForm]::FormC).ToUpperInvariant()
    $hmac = [Security.Cryptography.HMACSHA256]::new($script:IdKey)
    try {
        $hash = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($text))
        return 'h1:' + [BitConverter]::ToString($hash).Replace('-', '').ToLowerInvariant()
    } finally {
        $hmac.Dispose()
    }
}

# This function operates INSIDE the collector. No raw command line leaves it.
# Ambiguous/relative/secret-bearing commands are deliberately unresolved.
function Get-SafeTarget([AllowNull()][string]$raw) {
    if ([string]::IsNullOrWhiteSpace($raw) -or $raw.Length -gt 2048 -or
        $raw -match '[\x00-\x1F\x7F]') { return $null }
    $text = $raw.Trim()
    $candidate = $null
    if ($text.StartsWith('"')) {
        if ($text -cmatch '^"(?<exe>[^"]{1,1024})"(?=\s|$)') { $candidate = $Matches['exe'] }
    } elseif ($text -match '^(?<exe>.{1,1024}?\.(?:exe|com|cmd|bat|ps1|vbs|lnk))(?=\s|$)') {
        $candidate = $Matches['exe']
    }
    if ([string]::IsNullOrEmpty($candidate)) { return $null }
    $candidate = $candidate.Replace('/', '\')
    # Fail closed on option-looking command fragments and secondary executables.
    if ($candidate -match '(?:\s)(?:--?\w|/\w)' -or $candidate.Contains('=') -or
        $candidate -match '\.(?:exe|cmd|bat|com|ps1|vbs)\s') { return $null }
    if ($candidate.StartsWith('\\') -or $candidate.Contains('://') -or
        $candidate -match '["<>|;&@]' -or $candidate -match '[\x00-\x1F\x7F]') { return $null }
    # Only known Windows environment variable prefixes are allowed. Do not expand.
    if ($candidate -match '%') {
        if ($candidate -notmatch '^(?i:%(?:SystemRoot|windir|ProgramFiles|ProgramFiles\(x86\)|APPDATA|LOCALAPPDATA|USERPROFILE|TEMP|TMP)%)\\') {
            return $null
        }
        $afterPrefix = $candidate -replace '^(?i:%(?:SystemRoot|windir|ProgramFiles|ProgramFiles\(x86\)|APPDATA|LOCALAPPDATA|USERPROFILE|TEMP|TMP)%)\\', ''
        if ($afterPrefix.Contains('%')) { return $null }
    }
    if ($candidate -notmatch '^(?i:[A-Z]:\\|%[A-Za-z0-9()]+%\\|[A-Za-z0-9_.-]+\.(?:exe|com|cmd|bat|ps1|vbs|lnk)$)') {
        return $null
    }
    # Redact identity-bearing profile names before emitting paths.
    return [regex]::Replace($candidate, '(?i)^([A-Z]:\\Users\\)[^\\]+(?=\\|$)', '$1<redacted>')
}

function Emit([hashtable]$record) {
    [Console]::Out.WriteLine(($record | ConvertTo-Json -Depth 4 -Compress))
}
function Emit-Entry([string]$section, [string]$kind, [string]$scope,
                    [AllowNull()][string]$identity, [AllowNull()][string]$raw,
                    [hashtable]$metadata = @{}) {
    if ($script:Count -ge $Max) { $script:LimitHit = $true; return }
    $script:Count++
    $entry = @{
        t='entry';section=$section;kind=$kind;scope=$scope
        entry_id=(Get-EntryId $section $identity)
        target_path=(Get-SafeTarget $raw)
    }
    foreach ($key in $metadata.Keys) { $entry[$key] = $metadata[$key] }
    Emit $entry
}
function Emit-Issue([string]$section,[string]$code) {
    Emit @{t='issue';section=$section;code=$code}
}
function Emit-Done([string]$section) {
    if ($script:LimitHit) { Emit-Issue $section 'limit_reached' }
    else { Emit @{t='done';section=$section} }
}
function Error-Code($err) {
    if ($err.Exception -is [System.UnauthorizedAccessException] -or
        $err.Exception -is [System.Security.SecurityException] -or
        $err.Exception.HResult -eq -2147024891 -or
        $err.Exception.HResult -eq -2147217405) {
        return 'permission_denied'
    }
    return 'enumeration_error'
}

# Explicit 32/64-bit RegistryView, OpenSubKey(path,false) is read-only.
$hives = @(
    @{id='hkcu'; root=[Microsoft.Win32.RegistryHive]::CurrentUser; scope='user'},
    @{id='hklm'; root=[Microsoft.Win32.RegistryHive]::LocalMachine; scope='machine'}
)
$views = @(
    @{id='64';view=[Microsoft.Win32.RegistryView]::Registry64},
    @{id='32';view=[Microsoft.Win32.RegistryView]::Registry32}
)
foreach ($hive in $hives) {
    foreach ($view in $views) {
        foreach ($run in @('run','runonce')) {
            $section = 'registry_' + $hive.id + '_' + $view.id + '_' + $run
            if ($script:Count -ge $Max) { Emit-Issue $section 'limit_reached';continue }
            $base = $null
            $key = $null
            try {
                $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive.root,$view.view)
                $regPath = 'Software\Microsoft\Windows\CurrentVersion\'
                if ($run -eq 'run') { $regPath += 'Run' } else { $regPath += 'RunOnce' }
                $key = $base.OpenSubKey($regPath, $false)
                if ($null -ne $key) {
                    foreach ($valueName in $key.GetValueNames()) {
                        if ($script:Count -ge $Max) { $script:LimitHit = $true; break }
                        $value = $key.GetValue($valueName,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                        $target = $null
                        if ($value -is [string]) { $target = $value }
                        $kind = if ($run -eq 'run') { 'run' } else { 'run_once' }
                        # ValueName is hashed locally and never sent via stdout.
                        Emit-Entry $section $kind $hive.scope $valueName $target
                    }
                }
                Emit-Done $section
            } catch {
                Emit-Issue $section (Error-Code $_)
            } finally {
                if ($null -ne $key) { $key.Close() }
                if ($null -ne $base) { $base.Close() }
            }
        }
    }
}

$startupFolders = @(
    @{id='startup_user';name=[Environment+SpecialFolder]::Startup;scope='user'},
    @{id='startup_common';name=[Environment+SpecialFolder]::CommonStartup;scope='machine'}
)
foreach ($entry in $startupFolders) {
    $section = $entry.id
    if ($script:Count -ge $Max) { Emit-Issue $section 'limit_reached';continue }
    try {
        $folder = [Environment]::GetFolderPath($entry.name)
        if ([string]::IsNullOrWhiteSpace($folder) -or -not [IO.Directory]::Exists($folder)) {
            Emit-Issue $section 'unavailable'
            continue
        }
        $shortcuts = New-Object -ComObject WScript.Shell
        foreach ($f in [IO.Directory]::EnumerateFiles($folder)) {
            if ($script:Count -ge $Max) { $script:LimitHit = $true; break }
            $path = $f
            if ([IO.Path]::GetExtension($f) -ieq '.lnk') {
                try { $path = $shortcuts.CreateShortcut($f).TargetPath }
                catch { $path = $null }
            }
            Emit-Entry $section 'startup' $entry.scope $f $path
        }
        Emit-Done $section
    } catch {
        Emit-Issue $section (Error-Code $_)
    }
}

# Task Scheduler 2.0; task path + zero/one-based action index is the identity.
$section = 'task_scheduler'
if ($script:Count -ge $Max) { Emit-Issue $section 'limit_reached' }
else {
    try {
        $scheduler = New-Object -ComObject 'Schedule.Service'
        $scheduler.Connect()
        $queue = New-Object 'System.Collections.Generic.List[object]'
        $queue.Add($scheduler.GetFolder('\'))
        $at = 0
        $foldersSeen = 0
        $taskErrors = $false
        while ($at -lt $queue.Count -and $foldersSeen -lt 128 -and $script:Count -lt $Max) {
            $folder = $queue[$at];$at++;$foldersSeen++
            try {
                $tasks = $folder.GetTasks(1)
                for ($i=1; $i -le $tasks.Count; $i++) {
                    if ($script:Count -ge $Max) { $script:LimitHit = $true; break }
                    try {
                        $task = $tasks.Item($i)
                        $actions = $task.Definition.Actions
                        for ($j=1; $j -le $actions.Count; $j++) {
                            if ($script:Count -ge $Max) { $script:LimitHit = $true; break }
                            $action = $actions.Item($j)
                            $identity = [string]$task.Path + [char]0 + [string]$j
                            if ($action.Type -eq 0) {
                                Emit-Entry $section 'scheduled_task' 'machine' $identity ([string]$action.Path)
                            } else {
                                Emit-Entry $section 'scheduled_task' 'unknown' $identity $null
                            }
                        }
                    } catch { $taskErrors = $true }
                }
                $subs = $folder.GetFolders(0)
                for ($i=1; $i -le $subs.Count; $i++) {
                    if ($queue.Count -ge 128) { $script:LimitHit = $true; break }
                    $queue.Add($subs.Item($i))
                }
            } catch { $taskErrors = $true }
        }
        if ($at -lt $queue.Count) { $script:LimitHit = $true }
        if ($taskErrors) { Emit-Issue $section 'enumeration_error' }
        else { Emit-Done $section }
    } catch {
        Emit-Issue $section (Error-Code $_)
    }
}

# Optional permanent WMI subscriptions. No template text, WQL, names or SIDs
# travel to Rust. The executable may come from CommandLineTemplate when the
# ExecutablePath property is NULL; this must never be reported as harmless.
if ($EnableWmi) {
    $classes = @(
        @{id='wmi_filter';class='__EventFilter';kind='wmi_filter'},
        @{id='wmi_consumer';class='CommandLineEventConsumer';kind='wmi_consumer'},
        @{id='wmi_binding';class='__FilterToConsumerBinding';kind='wmi_binding'}
    )
    foreach ($class in $classes) {
        $section = $class.id
        if ($script:Count -ge $Max) { Emit-Issue $section 'limit_reached';continue }
        try {
            Get-CimInstance -Namespace 'root/subscription' -ClassName $class.class -OperationTimeoutSec 8 -ErrorAction Stop |
                ForEach-Object {
                    if ($script:Count -ge $Max) {
                        $script:LimitHit = $true
                    } else {
                        $identity = $null
                        $target = $null
                        $meta = @{}
                        if ($class.kind -eq 'wmi_binding') {
                            $identity = [string]$_.Filter + [char]0 + [string]$_.Consumer
                        } else {
                            $identity = [string]$_.Name
                        }
                        if ($class.kind -eq 'wmi_consumer') {
                            $exe = [string]$_.ExecutablePath
                            $template = [string]$_.CommandLineTemplate
                            $hasExe = -not [string]::IsNullOrWhiteSpace($exe)
                            $hasTemplate = -not [string]::IsNullOrWhiteSpace($template)
                            $meta['template_present'] = $hasTemplate
                            $meta['template_dynamic_target'] = 'unknown'
                            $meta['target_source'] = 'unresolved'
                            if ($hasExe) {
                                $target = $exe
                                $meta['target_source'] = 'executable_path'
                                $meta['template_dynamic_target'] = 'not_applicable'
                            } elseif ($hasTemplate) {
                                # The first token may be a variable substituted by WMI.
                                $token = $null
                                if ($template.TrimStart() -match '^"([^"]*)"') {
                                    $token = $Matches[1]
                                } elseif ($template.TrimStart() -match '^\S+') {
                                    $token = $Matches[0]
                                }
                                if ($token -match '%[^%]+%' -or $token -match '^\$') {
                                    $meta['template_dynamic_target'] = 'possible'
                                    $meta['target_source'] = 'template_dynamic'
                                } else {
                                    $meta['template_dynamic_target'] = 'not_observed'
                                    # Get-SafeTarget will extract only a static first executable.
                                    $target = $template
                                    $meta['target_source'] = 'template_static'
                                }
                            }
                            if ($null -eq (Get-SafeTarget $target) -and $hasTemplate -and -not $hasExe -and
                                $meta['target_source'] -ne 'template_dynamic') {
                                $meta['target_source'] = 'template_unresolved'
                            }
                        }
                        Emit-Entry $section $class.kind 'machine' $identity $target $meta
                    }
                }
            Emit-Done $section
        } catch {
            Emit-Issue $section (Error-Code $_)
        }
    }
}
