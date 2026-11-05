//! A bounded subprocess runner. Command and arguments must be static, never fixture-derived.
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

pub const MAX_OUTPUT_BYTES: u64 = 8_192;

#[derive(Debug, PartialEq, Eq)]
pub enum RunFailure {
    PermissionDenied,
    SpawnFailed,
    Timeout,
    NonZeroExit,
    OutputTooLarge,
    OutputFailed,
}

/// Enforces a wall-clock deadline and a stdout cap. Stderr is discarded because
/// localized host errors might disclose account names, paths or volume IDs.
pub fn run_program(
    executable: &Path,
    args: &[&str],
    deadline: Duration,
) -> Result<Vec<u8>, RunFailure> {
    let mut process = Command::new(executable)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::PermissionDenied {
                RunFailure::PermissionDenied
            } else {
                RunFailure::SpawnFailed
            }
        })?;
    let stdout = process.stdout.take().ok_or(RunFailure::OutputFailed)?;
    let reader = thread::spawn(move || {
        let mut output = Vec::new();
        let mut bounded = stdout.take(MAX_OUTPUT_BYTES + 1);
        bounded.read_to_end(&mut output).map(|_| output)
    });

    let started = Instant::now();
    let status = loop {
        match process.try_wait() {
            Ok(Some(exit)) => break exit,
            Ok(None) if started.elapsed() < deadline => thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                let _ = process.kill();
                let _ = process.wait();
                let _ = reader.join();
                return Err(RunFailure::Timeout);
            }
            Err(_) => {
                let _ = process.kill();
                let _ = process.wait();
                let _ = reader.join();
                return Err(RunFailure::OutputFailed);
            }
        }
    };
    let output = reader
        .join()
        .map_err(|_| RunFailure::OutputFailed)?
        .map_err(|_| RunFailure::OutputFailed)?;
    if output.len() as u64 > MAX_OUTPUT_BYTES {
        return Err(RunFailure::OutputTooLarge);
    }
    if !status.success() {
        return Err(RunFailure::NonZeroExit);
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn harmless_slow_process_is_stopped() {
        let started = Instant::now();
        let result = run_program(
            Path::new("/bin/sleep"),
            &["2"],
            Duration::from_millis(50),
        );
        assert_eq!(result, Err(RunFailure::Timeout));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[cfg(unix)]
    #[test]
    fn clean_small_output_is_accepted() {
        let output = run_program(
            Path::new("/bin/echo"),
            &["safe"],
            Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(output, b"safe\n");
    }
}
