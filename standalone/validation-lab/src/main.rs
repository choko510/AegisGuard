use std::env;
use std::path::Path;
use validation_lab::{error_output, generate, summarize, verify};

fn usage() -> &'static str {
    "usage: validation-lab generate --out <dir> [--seed 42] [--profile all|case-id]\n       validation-lab verify --dir <dir>\n       validation-lab summarize --expected <manifest.json> --actual <report.jsonl>"
}

fn option(args: &[String], name: &str) -> Result<Option<String>, String> {
    let mut value = None;
    let mut i = 0;
    while i < args.len() {
        if args[i] == name {
            if value.is_some() || i + 1 == args.len() || args[i + 1].starts_with("--") {
                return Err(format!("duplicate or empty {name}"));
            }
            value = Some(args[i + 1].clone());
            i += 2;
        } else {
            i += 1;
        }
    }
    Ok(value)
}

fn required(args: &[String], name: &str) -> Result<String, String> {
    option(args, name)?.ok_or_else(|| format!("missing {name}"))
}

fn parse() -> Result<serde_json::Value, String> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        return Err(usage().to_string());
    }
    let allowed: &[&str] = match args[0].as_str() {
        "generate" => &["--out", "--seed", "--profile"],
        "verify" => &["--dir"],
        "summarize" => &["--expected", "--actual"],
        _ => return Err(usage().to_string()),
    };
    let mut i = 1;
    while i < args.len() {
        if !allowed.contains(&args[i].as_str()) || i + 1 >= args.len() {
            return Err(usage().to_string());
        }
        i += 2;
    }
    match args[0].as_str() {
        "generate" => {
            let seed = option(&args, "--seed")?
                .unwrap_or_else(|| "42".into())
                .parse::<u64>()
                .map_err(|_| "invalid --seed")?;
            let profile = option(&args, "--profile")?.unwrap_or_else(|| "all".into());
            generate(Path::new(&required(&args, "--out")?), seed, &profile)
        }
        "verify" => verify(Path::new(&required(&args, "--dir")?)),
        "summarize" => summarize(
            Path::new(&required(&args, "--expected")?),
            Path::new(&required(&args, "--actual")?),
        ),
        _ => Err(usage().to_string()),
    }
}

fn main() {
    match parse() {
        Ok(value) => {
            println!("{value}");
            if value["status"] != "complete" {
                std::process::exit(1);
            }
        }
        Err(error) => {
            eprintln!("{error}");
            println!("{}", error_output(&error));
            std::process::exit(2);
        }
    }
}
