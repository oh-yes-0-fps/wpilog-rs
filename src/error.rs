use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("DataLog io error: {0:?}")]
    Io(#[from] std::io::Error),
    #[error("Record serialization error: {0:?}")]
    RecordSerialize(String),
    #[error("Record deserialization error: {0:?}")]
    RecordDeserialize(String),
    #[error("Record type error: {0:?}")]
    RecordType(String),
    #[error("Record byte reader was short: {0}")]
    RecordReaderOutOfBounds(&'static str),
    #[error("Attempted to modify a read only data log")]
    DataLogReadOnly,
    #[error("DataLog entry does not exist")]
    NoSuchEntry,
    #[error("Outside entry lifetime")]
    OutsideEntryLifetime,
    #[error("DataLog entry already exists")]
    EntryAlreadyExists,
    #[error("Dile not a valid DataLog")]
    InvalidDataLog,
    #[error("File doesn't exist")]
    FileDoesNotExist,
    #[error("File already exists")]
    FileAlreadyExists,
    #[error("Retro entry data")]
    RetroEntryData,
}

#[inline(always)]
pub(crate) fn log_result<T, E: std::error::Error>(result: Result<T, E>) -> Result<T, E> {
    #[cfg(feature = "tracing")]
    match &result {
        Err(err) => {
            tracing::error!("{}", err)
        }
        _ => {}
    };
    result
}
