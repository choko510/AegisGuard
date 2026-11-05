//! Independent offline software inventory and conservative advisory matching.
//! No network client, subprocess execution, or registry mutation paths exist.

pub mod inventory;
pub mod matching;
pub mod model;
#[cfg(windows)]
mod registry;

use std::io::Read;
use std::path::Path;

pub fn read_bounded(path: &Path, max_bytes: u64) -> Result<Vec<u8>, String> {
    let meta = std::fs::symlink_metadata(path).map_err(|_| "input cannot be inspected".to_string())?;
    if !meta.file_type().is_file() || meta.len() > max_bytes {
        return Err("input must be a regular non-symlink file within the byte limit".into());
    }
    let file = std::fs::File::open(path).map_err(|_| "input cannot be opened".to_string())?;
    if !file.metadata().map_err(|_| "input metadata unavailable".to_string())?.is_file() {
        return Err("input is not a regular file".into());
    }
    let mut data = Vec::new();
    file.take(max_bytes + 1).read_to_end(&mut data).map_err(|_| "input read failed".to_string())?;
    if data.len() as u64 > max_bytes { return Err("input changed or exceeds byte limit".into()); }
    Ok(data)
}
pub fn inspect_fixture_bytes(data: &[u8]) -> Result<model::InventoryReport, String> {
    if data.len() > 1024 * 1024 { return Err("fixture byte limit exceeded".into()); }
    let fixture = serde_json::from_slice::<model::Fixture>(data)
        .map_err(|_| "malformed fixture JSON".to_string())?;
    inventory::inspect_fixture(fixture)
}
pub fn match_bytes(inventory_data: &[u8], advisory_data: &[u8], now: u64) -> Result<model::MatchReport, String> {
    if inventory_data.len() > 1024 * 1024 || advisory_data.len() > 2 * 1024 * 1024 {
        return Err("input byte limit exceeded".into());
    }
    let inventory = serde_json::from_slice::<model::InventoryReport>(inventory_data)
        .map_err(|_| "malformed inventory JSON".to_string())?;
    let batch = serde_json::from_slice::<model::AdvisoryBatch>(advisory_data)
        .map_err(|_| "malformed advisory JSON".to_string())?;
    matching::match_advisories(inventory, batch, now)
}
