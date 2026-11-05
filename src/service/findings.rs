//! Correlation findings persisted by the service for IPC readers.
use super::Layout;
use crate::{store, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const MAX_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FindingsDoc {
    pub schema: u32,
    pub updated_at_unix_ms: u64,
    /// Time window of events the findings were computed over.
    pub window: Value,
    /// Rule statuses (evaluable / missing sources).
    pub rules: Vec<Value>,
    pub findings: Vec<Value>,
}

pub fn path(layout: &Layout) -> std::path::PathBuf {
    layout.data_dir.join("findings.json")
}

pub fn load(layout: &Layout) -> Result<Option<FindingsDoc>> {
    let parse = |b: &[u8]| -> Result<FindingsDoc> { Ok(serde_json::from_slice(b)?) };
    Ok(store::load(&path(layout), MAX_BYTES, parse)?.map(|(d, _)| d))
}

pub fn save(layout: &Layout, doc: &FindingsDoc) -> Result<()> {
    let bytes = serde_json::to_vec(doc)?;
    store::store(&path(layout), &bytes, |b| {
        serde_json::from_slice::<FindingsDoc>(b)
            .map(|_| ())
            .map_err(Into::into)
    })
}
