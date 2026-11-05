//! Size-bounded, rotating JSONL report output. Rotation only ever renames or
//! removes files whose first line is an AegisGuard report, so pointing
//! `--output` at an unrelated file fails instead of overwriting it.
use crate::{store, Result};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub struct JsonlLog {
    path: PathBuf,
    file: File,
    size: u64,
    max_bytes: u64,
    generations: u32,
}

fn generation_path(path: &Path, n: u32) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".{n}"));
    path.with_file_name(name)
}

/// Whether a non-empty file starts with an AegisGuard scan report line.
fn is_aegisguard_jsonl(path: &Path) -> Result<bool> {
    let mut first = String::new();
    BufReader::new(File::open(path)?.take(1024 * 1024)).read_line(&mut first)?;
    let Ok(value) = serde_json::from_str::<serde_json::Value>(first.trim_end()) else {
        return Ok(false);
    };
    Ok(value.get("path").is_some() && value.get("risk").is_some())
}

fn open_append(path: &Path) -> Result<File> {
    let existed = path.exists();
    let file = OpenOptions::new().append(true).create(true).open(path)?;
    if !existed {
        store::restrict_to_owner(path)?;
    }
    Ok(file)
}

impl JsonlLog {
    pub fn open(path: &Path, max_bytes: u64, generations: u32) -> Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let size = match fs::metadata(path) {
            Ok(meta) => meta.len(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
            Err(e) => return Err(e.into()),
        };
        if size > 0 && !is_aegisguard_jsonl(path)? {
            return Err(format!(
                "Refusing to append to {}: it is not an AegisGuard JSONL report",
                path.display()
            )
            .into());
        }
        let mut file = open_append(path)?;
        let mut size = size;
        if size > 0 {
            // A crash can leave a partial last line; terminate it so the
            // following records stay parseable line by line.
            let mut last = [0u8];
            let mut reader = File::open(path)?;
            reader.seek(SeekFrom::End(-1))?;
            reader.read_exact(&mut last)?;
            if last[0] != b'\n' {
                file.write_all(b"\n")?;
                size += 1;
            }
        }
        Ok(Self {
            path: path.to_path_buf(),
            file,
            size,
            max_bytes,
            generations,
        })
    }

    pub fn write_line(&mut self, line: &str) -> Result<()> {
        let needed = line.len() as u64 + 1;
        if self.size > 0 && self.size.saturating_add(needed) > self.max_bytes {
            self.rotate()?;
        }
        let mut buf = Vec::with_capacity(line.len() + 1);
        buf.extend_from_slice(line.as_bytes());
        buf.push(b'\n');
        self.file.write_all(&buf)?;
        self.file.flush()?;
        self.size += needed;
        Ok(())
    }

    fn rotate(&mut self) -> Result<()> {
        if self.generations == 0 {
            return Err(format!(
                "{} reached its size limit and rotation is disabled",
                self.path.display()
            )
            .into());
        }
        let oldest = generation_path(&self.path, self.generations);
        if oldest.exists() {
            if !is_aegisguard_jsonl(&oldest)? {
                return Err(format!(
                    "Refusing to remove {}: it is not an AegisGuard JSONL report",
                    oldest.display()
                )
                .into());
            }
            fs::remove_file(&oldest)?;
        }
        for n in (1..self.generations).rev() {
            let from = generation_path(&self.path, n);
            if from.exists() {
                fs::rename(&from, generation_path(&self.path, n + 1))?;
            }
        }
        self.file.sync_all()?;
        fs::rename(&self.path, generation_path(&self.path, 1))?;
        self.file = open_append(&self.path)?;
        self.size = 0;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINE: &str = r#"{"path":"x.py","risk":"low_signal","pad":"0123456789"}"#;

    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("aegisguard-jsonl-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn rotates_and_keeps_a_bounded_number_of_generations() {
        let dir = temp_dir("rotate");
        let path = dir.join("scan.jsonl");
        let mut log = JsonlLog::open(&path, (LINE.len() as u64 + 1) * 2, 2).unwrap();
        for _ in 0..9 {
            log.write_line(LINE).unwrap();
        }
        drop(log);
        for p in [
            &path,
            &generation_path(&path, 1),
            &generation_path(&path, 2),
        ] {
            let text = fs::read_to_string(p).unwrap();
            assert!(text.lines().count() <= 2);
            assert!(text.lines().all(|l| l == LINE));
        }
        assert!(!generation_path(&path, 3).exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn refuses_to_append_to_unrelated_files() {
        let dir = temp_dir("foreign");
        let path = dir.join("notes.txt");
        fs::write(&path, "my notes\n").unwrap();
        assert!(JsonlLog::open(&path, 1024, 2).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "my notes\n");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn refuses_to_delete_an_unrelated_oldest_generation() {
        let dir = temp_dir("foreign-generation");
        let path = dir.join("scan.jsonl");
        fs::write(generation_path(&path, 1), "keep me\n").unwrap();
        let mut log = JsonlLog::open(&path, LINE.len() as u64 + 1, 1).unwrap();
        log.write_line(LINE).unwrap();
        assert!(log.write_line(LINE).is_err());
        assert_eq!(
            fs::read_to_string(generation_path(&path, 1)).unwrap(),
            "keep me\n"
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn partial_last_line_is_terminated_before_appending() {
        let dir = temp_dir("partial");
        let path = dir.join("scan.jsonl");
        fs::write(&path, format!("{LINE}\n{{\"path\":\"trunc")).unwrap();
        let mut log = JsonlLog::open(&path, 1 << 20, 2).unwrap();
        log.write_line(LINE).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        let lines: Vec<_> = text.lines().collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[2], LINE);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn disabled_rotation_stops_at_the_limit() {
        let dir = temp_dir("norotate");
        let path = dir.join("scan.jsonl");
        let mut log = JsonlLog::open(&path, LINE.len() as u64 + 1, 0).unwrap();
        log.write_line(LINE).unwrap();
        assert!(log.write_line(LINE).is_err());
        fs::remove_dir_all(dir).unwrap();
    }
}
