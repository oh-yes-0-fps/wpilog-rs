use std::path::{Path, PathBuf};

#[macro_use]
pub mod macros;

pub mod log;
pub(crate) mod records;
pub(crate) mod util;
pub mod error;

#[cfg(test)]
mod test;

///Microseconds
type WpiTimestamp = u64;
///A unique identifier for a data entry
type EntryId = u32;
///A string representing a data entry name
type EntryName = String;
///A string representing a data entry type
type EntryType = String;
///A string in json format representing data entry metadata
type EntryMetadata = String;
///an array of little endian bytes
type LeBytes = Vec<u8>;
///A little endian byte
type LeByte = u8;
///A hash map of entry id to entry types
type EntryTypeMap = std::collections::HashMap<EntryId, EntryType>;
///A hash map of entry id to entry names
type EntryIdToNameMap = bimap::BiMap::<EntryId, EntryName>;

pub fn sec_from_micros(micros: WpiTimestamp) -> f64 {
    micros as f64 / 1_000_000.0
}

pub fn now() -> WpiTimestamp {
    let now = std::time::SystemTime::now();
    let duration = now.duration_since(std::time::UNIX_EPOCH).unwrap();
    duration.as_micros() as WpiTimestamp
}

pub fn absolute_path(rel_path: &Path) -> PathBuf {
    //get the current working directory
    let cwd = std::env::current_dir().unwrap();
    //append the path to the current working directory
    cwd.join(rel_path)
}
