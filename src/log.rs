use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::PathBuf,
    sync::mpsc::{channel, Sender},
    thread::{self, JoinHandle},
};

use crate::{
    error::{log_result, DatalogError},
    now,
    records::{parse_records, ControlRecord, Record},
    EntryId, EntryIdToNameMap, EntryMetadata, EntryName, EntryType, WpiTimestamp,
};
use single_value_channel::{channel_starting_with as single_channel, Receiver as SingleReceiver};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub enum DataLogValue {
    Raw(Vec<u8>),
    Boolean(bool),
    Integer(i64),
    Float(f32),
    Double(f64),
    String(String),
    BooleanArray(Vec<bool>),
    IntegerArray(Vec<i64>),
    FloatArray(Vec<f32>),
    DoubleArray(Vec<f64>),
    StringArray(Vec<String>),
}

impl DataLogValue {
    pub fn get_data_type(&self) -> String {
        match self {
            DataLogValue::Raw(_) => "raw".to_string(),
            DataLogValue::Boolean(_) => "boolean".to_string(),
            DataLogValue::Integer(_) => "int64".to_string(),
            DataLogValue::Float(_) => "float".to_string(),
            DataLogValue::Double(_) => "double".to_string(),
            DataLogValue::String(_) => "string".to_string(),
            DataLogValue::BooleanArray(_) => "boolean[]".to_string(),
            DataLogValue::IntegerArray(_) => "int64[]".to_string(),
            DataLogValue::FloatArray(_) => "float[]".to_string(),
            DataLogValue::DoubleArray(_) => "double[]".to_string(),
            DataLogValue::StringArray(_) => "string[]".to_string(),
        }
    }

    pub fn matches_type(&self, e_type: &String) -> bool {
        match self {
            DataLogValue::Raw(_) => e_type == "raw",
            DataLogValue::Boolean(_) => e_type == "boolean",
            DataLogValue::Integer(_) => e_type == "int64",
            DataLogValue::Float(_) => e_type == "float",
            DataLogValue::Double(_) => e_type == "double",
            DataLogValue::String(_) => e_type == "string",
            DataLogValue::BooleanArray(_) => e_type == "boolean[]",
            DataLogValue::IntegerArray(_) => e_type == "int64[]",
            DataLogValue::FloatArray(_) => e_type == "float[]",
            DataLogValue::DoubleArray(_) => e_type == "double[]",
            DataLogValue::StringArray(_) => e_type == "string[]",
        }
    }
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub enum EntryLifeStatus {
    Alive(u64),
    Dead(u64, u64),
    NotBorn,
}

#[derive(Debug, Clone)]
pub(crate) struct Entry {
    pub name: EntryName,
    pub id: EntryId,
    pub marks: BTreeMap<WpiTimestamp, DataLogValue>,
    pub type_str: EntryType,
    pub metadata: EntryMetadata,
    pub lifetime: EntryLifeStatus,
    pub unflushed_timestamps: HashSet<WpiTimestamp>,
    pub latest_timestamp: WpiTimestamp,
}
impl Entry {
    pub(crate) fn new(
        name: EntryName,
        id: EntryId,
        type_str: EntryType,
        metadata: EntryMetadata,
        timestamp: WpiTimestamp,
    ) -> Self {
        Self {
            name,
            id,
            marks: BTreeMap::new(),
            type_str,
            metadata,
            lifetime: EntryLifeStatus::Alive(timestamp),
            unflushed_timestamps: HashSet::from([timestamp]),
            latest_timestamp: timestamp,
        }
    }

    pub(crate) fn add_mark(&mut self, timestamp: WpiTimestamp, value: DataLogValue) {
        self.marks.insert(timestamp, value);
        self.unflushed_timestamps.insert(timestamp);
    }

    pub(crate) fn kill(&mut self, timestamp: WpiTimestamp) {
        match self.lifetime {
            EntryLifeStatus::Alive(start) => {
                self.lifetime = EntryLifeStatus::Dead(start, timestamp);
                self.unflushed_timestamps.insert(timestamp);
            }
            _ => {}
        }
    }

    pub(crate) fn get_lifespan(&self) -> (u64, Option<u64>) {
        match self.lifetime {
            EntryLifeStatus::Alive(start) => (start, None),
            EntryLifeStatus::Dead(start, end) => (start, Some(end)),
            _ => (0, None),
        }
    }

    pub(crate) fn is_finsihed(&self) -> bool {
        match self.lifetime {
            EntryLifeStatus::Dead(_, _) => true,
            _ => false,
        }
    }

    pub(crate) fn free_old_marks(&mut self, before: WpiTimestamp) {
        let mut to_remove = Vec::new();
        for (timestamp, _) in &self.marks {
            if *timestamp < before {
                to_remove.push(*timestamp);
            }
        }
        //needs to be 2 separate loops to avoid borrowing issues
        for timestamp in to_remove {
            self.marks.remove(&timestamp);
        }
    }

    #[allow(dead_code)]
    pub(crate) fn get_records(&self) -> Vec<Record> {
        let lifespan = self.get_lifespan();

        let mut records = Vec::new();
        records.push(Record::Control(
            ControlRecord::Start(
                self.name.clone(),
                self.type_str.clone(),
                self.metadata.clone(),
            ),
            lifespan.0,
            self.id,
        ));
        for (timestamp, value) in &self.marks {
            records.push(Record::Data(value.clone().into(), *timestamp, self.id));
        }
        if lifespan.1.is_some() {
            records.push(Record::Control(
                ControlRecord::Finish,
                lifespan.1.unwrap(),
                self.id,
            ));
        }
        records
    }

    #[inline]
    pub(crate) fn get_unflushed_records(&mut self) -> Vec<Record> {
        let lifespan = self.get_lifespan();

        let mut records = Vec::new();
        if self.unflushed_timestamps.contains(&lifespan.0) {
            records.push(Record::Control(
                ControlRecord::Start(
                    self.name.clone(),
                    self.type_str.clone(),
                    self.metadata.clone(),
                ),
                lifespan.0,
                self.id,
            ));
            self.unflushed_timestamps.remove(&lifespan.0);
        }
        let mut opt_finish = None;
        if let Some(end) = lifespan.1 {
            if self.unflushed_timestamps.contains(&end) {
                opt_finish = Some(Record::Control(ControlRecord::Finish, end, self.id));
            }
        }
        for timestamp in self.unflushed_timestamps.drain() {
            if let Some(value) = self.marks.get(&timestamp) {
                records.push(Record::Data(value.clone().into(), timestamp, self.id));
            }
        }
        if let Some(finish) = opt_finish {
            records.push(finish);
        }
        records
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IOType {
    ReadOnly,
    ReadWrite,
}

#[derive(Debug, Clone)]
pub struct CreateDataLogConfig {
    ///the absolute path to the file
    pub file_path: PathBuf,
    ///metadata for the file header
    pub metadata: String,
}

#[derive(Debug, Clone)]
pub struct OpenDataLogConfig {
    ///the absolute path to the file
    pub file_path: PathBuf,
    ///the type of io to use
    pub io_type: IOType,
}

#[derive(Debug)]
pub struct DataLog {
    //io
    file_name: String,
    fs_file: Option<File>,
    io_type: IOType,
    //data
    format_version: (u8, u8),
    header_metadata: String,
    id_to_name_map: EntryIdToNameMap,
    entries: HashMap<EntryId, Entry>,
    finished_entries: HashSet<EntryId>,
    summary: HashMap<EntryName, EntryType>
}

impl DataLog {
    ///A way to delete a datalog file without worrying if it actually is a datalog file
    pub fn delete(file_name: PathBuf) -> Result<(), DatalogError> {
        // does the file exist?
        if !file_name.exists() {
            return Err(DatalogError::FileDoesNotExist);
        } else {
            // does file end with .wpilog?
            if file_name.extension().unwrap() != "wpilog" {
                return Err(DatalogError::InvalidDataLog);
            } else {
                // delete the file
                fs::remove_file(file_name)?;
                return Ok(());
            }
        }
    }

    /// Creates a new DataLog file
    pub fn create(config: CreateDataLogConfig) -> Result<Self, DatalogError> {
        if config.file_path.exists() {
            return Err(DatalogError::FileAlreadyExists);
        }
        let mut this = Self {
            file_name: config.file_path.to_str().unwrap().to_string(),
            fs_file: None,
            io_type: IOType::ReadWrite,
            format_version: (1, 0),
            header_metadata: config.metadata,
            id_to_name_map: EntryIdToNameMap::new(),
            entries: HashMap::new(),
            finished_entries: HashSet::new(),
            summary: HashMap::new()
        };
        let file = OpenOptions::new()
            .read(true)
            .create(true)
            .append(true)
            .open(&this.file_name);
        if file.is_err() {
            return Err(DatalogError::Io(file.err().unwrap()));
        }
        this.fs_file = Some(file.unwrap());

        //write header
        let mut header = Vec::new();
        //add "WPILog" magic header
        header.extend_from_slice("WPILOG".as_bytes());
        //add format version
        header.push(this.format_version.0);
        header.push(this.format_version.1);
        //add metadatalength as a u32
        let metadata_len = this.header_metadata.len() as u32;
        header.extend_from_slice(&metadata_len.to_le_bytes());
        //add metadata
        header.extend_from_slice(this.header_metadata.as_bytes());
        //write header to file
        if let Err(err) = this.fs_file.as_mut().unwrap().write_all(&header) {
            return Err(DatalogError::Io(err));
        }
        this.fs_file.as_mut().unwrap().flush()?;

        cfg_tracing! { tracing::info!("Created datalog: {}", this.file_name ); };

        Ok(this)
    }

    /// Opens an existing DataLog file
    pub fn open(config: OpenDataLogConfig) -> Result<Self, DatalogError> {
        if !config.file_path.exists() {
            return Err(DatalogError::FileDoesNotExist);
        }
        let mut this = Self {
            file_name: config.file_path.to_str().unwrap().to_string(),
            fs_file: None,
            io_type: config.io_type,
            format_version: (0, 0),
            header_metadata: String::new(),
            id_to_name_map: EntryIdToNameMap::new(),
            entries: HashMap::new(),
            finished_entries: HashSet::new(),
            summary: HashMap::new()
        };

        let file = OpenOptions::new()
            .read(true)
            .append(this.io_type == IOType::ReadWrite)
            .open(&this.file_name);
        if file.is_err() {
            return Err(DatalogError::Io(file.err().unwrap()));
        } else {
            cfg_tracing! { tracing::info!("Opened datalog: {}", this.file_name ); };
        }
        this.fs_file = Some(file.unwrap());

        this.populate();
        Ok(this)
    }

    fn populate(&mut self) {
        if self.fs_file.is_none() {
            panic!("File not open");
        }
        let mut file = self.fs_file.as_ref().unwrap();
        //read bytes from file
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        let file_magic_header = String::from_utf8(bytes[0..6].to_vec()).unwrap();
        if file_magic_header != "WPILOG" {
            panic!("Invalid file header");
        }
        self.format_version.0 = bytes[6];
        self.format_version.1 = bytes[7];
        //skip next 2 bytes
        let mut index = 8;
        //parse next 4 bytes as u32
        let metadata_len = u32::from_le_bytes(bytes[index..index + 4].try_into().unwrap());
        index += 4;
        //parse next metadata_len bytes as metadata
        self.header_metadata =
            String::from_utf8(bytes[index..index + metadata_len as usize].to_vec()).unwrap();
        //skip metadata_len bytes
        index += metadata_len as usize;

        //pass the rest of the bytes into parse record
        let records = parse_records(bytes[index..bytes.len()].to_vec());
        for record in records {
            log_result(self.add_record(record)).ok();
        }
        self.clear_unflush();
        cfg_tracing! { tracing::info!("Populated log {}", self.file_name); };
    }

    fn add_record(&mut self, record: Record) -> Result<(), DatalogError> {
        let entry_exists = self.entries.contains_key(&record.get_id());
        if record.is_control() {
            let control_rec = record.as_control().unwrap();
            if control_rec.is_start() {
                if entry_exists {
                    cfg_tracing! { tracing::warn!("Received start for existing entry"); };
                    Err(DatalogError::EntryAlreadyExists)
                } else {
                    let entry_name = control_rec.get_entry_name().unwrap().clone();
                    let entry_type = control_rec.get_entry_type().unwrap().clone();
                    let entry_id = record.get_id();
                    let entry_metadata = control_rec.get_entry_metadata().unwrap().clone();
                    let timestamp = record.get_timestamp();

                    self.id_to_name_map.insert(entry_id, entry_name.clone());
                    self.summary.insert(entry_name.clone(), entry_type.clone());

                    let entry =
                        Entry::new(entry_name, entry_id, entry_type, entry_metadata, timestamp);

                    cfg_tracing! { tracing::debug!("Received start for entry {:?}", entry.name); };

                    self.entries.insert(entry_id, entry);
                    Ok(())
                }
            } else if let Some(new_metadata) = control_rec.get_entry_metadata() {
                if entry_exists {
                    let entry = self.entries.get_mut(&record.get_id()).unwrap();
                    entry.metadata = new_metadata.clone();
                    cfg_tracing! { tracing::debug!("Received metadata for entry {:?}", entry.name); };
                    Ok(())
                } else {
                    cfg_tracing! { tracing::warn!("Received metadata for non-existent entry"); };
                    Err(DatalogError::NoSuchEntry)
                }
            } else {
                if entry_exists {
                    let entry = self.entries.get_mut(&record.get_id()).unwrap();
                    self.summary.remove(&entry.name);
                    entry.kill(record.get_timestamp());
                    self.finished_entries.insert(record.get_id());
                    cfg_tracing! { tracing::debug!("Received finish for entry {:?}", entry.name); };
                    Ok(())
                } else {
                    cfg_tracing! { tracing::warn!("Received finish for non-existent entry"); };
                    Err(DatalogError::NoSuchEntry)
                }
            }
        } else if entry_exists {
            let entry = self.entries.get_mut(&record.get_id()).unwrap();

            let data_rec = record.as_data().unwrap();

            //type check
            if !data_rec.matches_type(&entry.type_str) {
                cfg_tracing! { tracing::warn!("Received data for entry with wrong type"); };
                return Err(DatalogError::RecordType(
                    entry.type_str.clone() + &data_rec.get_data_type(),
                ));
            }

            //is finsihsed check
            if entry.is_finsihed() {
                cfg_tracing! { tracing::warn!("Received data for finished entry"); };
                return Err(DatalogError::NoSuchEntry);
            }

            //chronological check
            let timestamp = record.get_timestamp();
            if timestamp >= entry.latest_timestamp {
                entry.latest_timestamp = timestamp;
                entry.add_mark(timestamp, data_rec.clone().into())
            } else if timestamp < entry.get_lifespan().0 {
                //timestamp is before the entry was started
                cfg_tracing!(tracing::warn!("Received data thats too befor an entry was started"););
                return Err(DatalogError::RetroEntryData);
            } else if timestamp < entry.latest_timestamp {
                //timestamp is before the latest timestamp but after the entry was started
                cfg_tracing! { tracing::warn!("Received retro data in append mode"); };
                return Err(DatalogError::RetroEntryData);
            }
            cfg_tracing! { tracing::debug!("Received data for entry {:?}", entry.name); };
            Ok(())
        } else {
            cfg_tracing! { tracing::warn!("Received data for non-existent entry"); };
            Err(DatalogError::NoSuchEntry)
        }
    }

    pub fn flush(&mut self) -> Result<(), DatalogError> {
        if self.io_type == IOType::ReadOnly {
            cfg_tracing! { tracing::warn!("Attempted to write to read only log"); };
            return Err(DatalogError::DataLogReadOnly);
        }
        let mut buf = Vec::new();
        for entry in self.entries.values_mut() {
            for record in entry.get_unflushed_records() {
                buf.extend(record.to_binary());
            }
        }
        self.fs_file.as_mut().unwrap().write_all(&buf).unwrap();
        self.fs_file.as_mut().unwrap().flush().unwrap();
        Ok(())
    }

    pub fn as_daemon(self) -> DataLogDaemon {
        DataLogDaemon::spawn(self, 4.0)
    }

    pub fn free_old_data(&mut self, before: WpiTimestamp) {
        for entry in self.entries.values_mut() {
            entry.free_old_marks(before);
        }
    }
}

impl Drop for DataLog {
    fn drop(&mut self) {
        self.finish_unfinished();
        self.flush().ok();
    }
}

//write stuff
impl DataLog {
    pub fn append_to_entry(
        &mut self,
        entry_name: String,
        value: DataLogValue,
    ) -> Result<(), DatalogError> {
        self.append_to_entry_timestamp(entry_name, value, now())
    }

    pub fn append_to_entry_timestamp(
        &mut self,
        entry_name: String,
        value: DataLogValue,
        timestamp: WpiTimestamp,
    ) -> Result<(), DatalogError> {
        if self.io_type == IOType::ReadOnly {
            cfg_tracing! { tracing::warn!("Attempted to write to read only log"); };
            return Err(DatalogError::DataLogReadOnly);
        }
        let entry_id = self.id_to_name_map.get_by_right(&entry_name);
        if entry_id.is_none() {
            cfg_tracing! { tracing::warn!("Attempted to append to non-existent entry"); };
            return Err(DatalogError::NoSuchEntry);
        }
        let record = Record::Data(value.into(), timestamp, *entry_id.unwrap());
        self.add_record(record)
    }

    pub fn create_entry(
        &mut self,
        entry_name: String,
        entry_type: String,
        metadata: String,
    ) -> Result<(), DatalogError> {
        self.create_entry_timestamp(entry_name, entry_type, metadata, now())
    }

    pub fn create_entry_timestamp(
        &mut self,
        entry_name: String,
        entry_type: String,
        metadata: String,
        timestamp: WpiTimestamp,
    ) -> Result<(), DatalogError> {
        if self.io_type == IOType::ReadOnly {
            cfg_tracing! { tracing::warn!("Attempted to write to read only log"); };
            return Err(DatalogError::DataLogReadOnly);
        }
        let entry_id = self.id_to_name_map.get_by_right(&entry_name);
        if entry_id.is_some() {
            cfg_tracing! { tracing::warn!("Attempted to create existing entry"); };
            return Err(DatalogError::EntryAlreadyExists);
        }
        let next_id = if !self.entries.is_empty() {
            *self.entries.keys().max().unwrap() + 1
        } else {
            1
        };
        let record = Record::Control(
            ControlRecord::Start(entry_name.clone(), entry_type.clone(), metadata.clone()),
            timestamp,
            next_id,
        );
        self.add_record(record)
    }

    pub fn kill_entry(&mut self, entry_name: String) -> Result<(), DatalogError> {
        if self.io_type == IOType::ReadOnly {
            cfg_tracing! { tracing::warn!("Attempted to write to read only log"); };
            return Err(DatalogError::DataLogReadOnly);
        }
        let entry_id = self.id_to_name_map.get_by_right(&entry_name);
        if entry_id.is_none() {
            cfg_tracing! { tracing::warn!("Attempted to finish non-existent entry"); };
            return Err(DatalogError::NoSuchEntry);
        }
        let record = Record::Control(ControlRecord::Finish, now(), *entry_id.unwrap());
        self.add_record(record)
    }

    fn clear_unflush(&mut self) {
        for entry in self.entries.values_mut() {
            entry.unflushed_timestamps.clear();
        }
    }

    fn finish_unfinished(&mut self) {
        for entry in self.entries.values_mut() {
            if entry.get_lifespan().1.is_none() {
                entry.kill(now());
            }
        }
    } 
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DataLogResponse {
    pub value: DataLogValue,
    pub timestamp: WpiTimestamp,
    pub entry_id: EntryId,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DatalogEntryResponse {
    pub name: EntryName,
    pub id: EntryId,
    pub entry_type: EntryType,
    pub metadata: EntryMetadata,
    pub life_status: EntryLifeStatus,
    pub marks: Vec<DataLogResponse>,
}

//read stuff
impl DataLog {
    pub fn get_entry_name(&self, id: EntryId) -> Option<&EntryName> {
        self.id_to_name_map.get_by_left(&id)
    }

    pub fn get_entry_id(&self, name: &EntryName) -> Option<&EntryId> {
        self.id_to_name_map.get_by_right(name)
    }

    #[inline(always)]
    fn get_entry_from_name(&self, entry_name: &EntryName) -> Option<&Entry> {
        let entry_id = self.id_to_name_map.get_by_right(entry_name);
        if entry_id.is_none() {
            return None;
        }
        self.entries.get(entry_id.unwrap())
    }

    #[allow(dead_code)]
    fn get_entry_from_id(&self, entry_id: &EntryId) -> Option<&Entry> {
        self.entries.get(entry_id)
    }

    pub fn get_entry_life(&self, entry_name: EntryName) -> EntryLifeStatus {
        if let Some(entry) = self.get_entry_from_name(&entry_name) {
            entry.lifetime
        } else {
            EntryLifeStatus::NotBorn
        }
    }

    pub fn get_entry_type(&self, entry_name: EntryName) -> Option<&EntryType> {
        if let Some(entry) = self.get_entry_from_name(&entry_name) {
            Some(&entry.type_str)
        } else {
            None
        }
    }

    pub fn get_entry_metadata(&self, entry_name: EntryName) -> Option<&EntryMetadata> {
        if let Some(entry) = self.get_entry_from_name(&entry_name) {
            Some(&entry.metadata)
        } else {
            None
        }
    }

    fn get_value_just_before_timestamp(
        entry: &Entry,
        when: WpiTimestamp,
    ) -> Option<DataLogResponse> {
        if let Some(val) = entry.marks.get(&when) {
            Some(DataLogResponse {
                value: val.clone(),
                timestamp: when,
                entry_id: entry.id,
            })
        } else if entry.marks.keys().len() == 0 {
            None
        } else if entry.marks.keys().len() == 1 {
            let key = entry.marks.keys().next().unwrap();
            Some(DataLogResponse {
                value: entry.marks.get(key).unwrap().clone(),
                timestamp: *key,
                entry_id: entry.id,
            })
        } else if entry.marks.keys().min().unwrap() > &when {
            None
        } else if entry.marks.keys().max().unwrap() < &when {
            let key = entry.marks.keys().max().unwrap();
            Some(DataLogResponse {
                value: entry.marks.get(key).unwrap().clone(),
                timestamp: *key,
                entry_id: entry.id,
            })
        } else {
            let keys = entry.marks.keys().collect::<Vec<_>>();
            //find the two keys that are just below and just above when
            //the keys are sorted, so we can use binary search
            let mut lower_bound = 0;
            let mut upper_bound = keys.len() - 1;
            let mut mid = (lower_bound + upper_bound) / 2;
            while lower_bound < upper_bound {
                if keys[mid] < &when {
                    lower_bound = mid + 1;
                } else if keys[mid] > &when {
                    upper_bound = mid - 1;
                } else {
                    break;
                }
                mid = (lower_bound + upper_bound) / 2;
            }
            //mid is now the index of the key that is just below when
            let lower_key = keys[mid];
            Some(DataLogResponse {
                value: entry.marks.get(lower_key).unwrap().clone(),
                timestamp: *lower_key,
                entry_id: entry.id,
            })
        }
    }

    pub fn get_entry_value(
        &self,
        entry_name: EntryName,
        when: WpiTimestamp,
    ) -> Result<DataLogResponse, DatalogError> {
        if let Some(entry) = self.get_entry_from_name(&entry_name) {
            //is timestamp within the entry's lifetime?
            let lifespan = entry.get_lifespan();
            if when < lifespan.0 {
                Err(DatalogError::OutsideEntryLifetime)
            } else if let Some(end_time) = lifespan.1 {
                if when > end_time {
                    Err(DatalogError::OutsideEntryLifetime)
                } else {
                    DataLog::get_value_just_before_timestamp(entry, when)
                        .ok_or(DatalogError::OutsideEntryLifetime)
                }
            } else {
                DataLog::get_value_just_before_timestamp(entry, when)
                    .ok_or(DatalogError::OutsideEntryLifetime)
            }
        } else {
            Err(DatalogError::NoSuchEntry)
        }
    }

    pub fn get_last_entry_value(
        &self,
        entry_name: EntryName,
    ) -> Result<DataLogResponse, DatalogError> {
        if let Some(entry) = self.get_entry_from_name(&entry_name) {
            if entry.marks.keys().len() == 0 {
                Err(DatalogError::OutsideEntryLifetime)
            } else {
                let key = entry.marks.keys().max().unwrap();
                Ok(DataLogResponse {
                    value: entry.marks.get(key).unwrap().clone(),
                    timestamp: *key,
                    entry_id: entry.id,
                })
            }
        } else {
            Err(DatalogError::NoSuchEntry)
        }
    }

    pub fn get_entry(&self, entry_name: EntryName) -> Option<DatalogEntryResponse> {
        if let Some(entry) = self.get_entry_from_name(&entry_name) {
            let mut marks = Vec::new();
            for (timestamp, value) in entry.marks.iter() {
                marks.push(DataLogResponse {
                    value: value.clone(),
                    timestamp: *timestamp,
                    entry_id: entry.id,
                });
            }
            Some(DatalogEntryResponse {
                name: entry.name.clone(),
                id: entry.id,
                entry_type: entry.type_str.clone(),
                metadata: entry.metadata.clone(),
                life_status: entry.lifetime,
                marks,
            })
        } else {
            None
        }
    }

    pub fn get_all_entries(&self) -> Vec<DatalogEntryResponse> {
        let mut entries = Vec::new();
        for entry in self.entries.values() {
            let mut marks = Vec::new();
            for (timestamp, value) in entry.marks.iter() {
                marks.push(DataLogResponse {
                    value: value.clone(),
                    timestamp: *timestamp,
                    entry_id: entry.id,
                });
            }
            entries.push(DatalogEntryResponse {
                name: entry.name.clone(),
                id: entry.id,
                entry_type: entry.type_str.clone(),
                metadata: entry.metadata.clone(),
                life_status: entry.lifetime,
                marks,
            });
        }
        entries
    }

    pub fn get_summary(&self) -> HashMap<EntryName, EntryType> {
        self.summary.clone()
    }
}

#[derive(Debug, Clone)]
pub struct DataLogDaemonSender {
    closed: bool,
    sender: Sender<(EntryName, Record)>,
}
impl DataLogDaemonSender {
    pub fn start_entry(
        &self,
        name: EntryName,
        entry_type: EntryType,
        metadata: Option<String>,
    ) -> Result<(), DatalogError> {
        if self.closed {
            return Err(DatalogError::DataLogDaemonClosed);
        }
        self.sender.send((
            String::new(),
            Record::Control(
                ControlRecord::Start(name, entry_type, metadata.unwrap_or_default()),
                now(),
                0,
            ),
        ))?;
        Ok(())
    }

    pub fn append_to_entry(
        &self,
        name: EntryName,
        value: DataLogValue,
    ) -> Result<(), DatalogError> {
        if self.closed {
            return Err(DatalogError::DataLogDaemonClosed);
        }
        self.sender
            .send((name, Record::Data(value.into(), now(), 0)))?;
        Ok(())
    }

    pub fn append_to_entry_with_timestamp(
        &self,
        name: EntryName,
        value: DataLogValue,
        timestamp: WpiTimestamp,
    ) -> Result<(), DatalogError> {
        if self.closed {
            return Err(DatalogError::DataLogDaemonClosed);
        }
        self.sender
            .send((name, Record::Data(value.into(), timestamp, 0)))?;
        Ok(())
    }

    pub fn finish_entry(&self, name: EntryName) -> Result<(), DatalogError> {
        if self.closed {
            return Err(DatalogError::DataLogDaemonClosed);
        }
        self.sender
            .send((name, Record::Control(ControlRecord::Finish, now(), 0)))?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct DataLogDaemon {
    thread_handle: Option<JoinHandle<()>>,
    sender: DataLogDaemonSender,
    receiver: SingleReceiver<Vec<DatalogEntryResponse>>,
    summary: SingleReceiver<HashMap<EntryName, EntryType>>
}
impl DataLogDaemon {
    fn spawn(datalog: DataLog, max_data_age_hrs: f64) -> DataLogDaemon {
        let (sender, receiver) = channel::<(EntryName, Record)>();
        let (updatee, updater) = single_channel::<Vec<DatalogEntryResponse>>(Vec::new());
        let (summary_updatee, summary_updater) = single_channel::<HashMap<EntryName, EntryType>>(HashMap::new());
        let thread_handle = thread::Builder::new()
            .name("DataLogDaemon".to_owned())
            .spawn(move || {
            let max_age = (max_data_age_hrs * 60.0 * 60.0 * 1000.0 * 1000.0) as WpiTimestamp;
            let thirty_min = 30u64 * 60 * 1000 * 1000;
            let mut last_free = now();
            let mut log = datalog;
            let mut cycle_count = 0;
            loop {
                if let Ok(data) = receiver.try_recv() {
                    if data.0.len() == 0 {
                        log.add_record(data.1).ok();
                    } else {
                        let id = log.get_entry_id(&data.0);
                        if id.is_none() {
                            continue;
                        }
                        let old_rec = data.1;
                        let new_rec = Record::Data(
                            old_rec.as_data().unwrap().clone(),
                            old_rec.get_timestamp(),
                            *id.unwrap(),
                        );
                        log.add_record(new_rec).ok();
                        summary_updater.update(log.get_summary()).ok();
                    }
                    if cycle_count > 5 {
                        updater.update(log.get_all_entries()).ok();
                        log.flush().ok();
                        cycle_count = 0;
                    }
                    cycle_count += 1;
                }
                if now() - last_free > max_age + thirty_min{
                    log.free_old_data(now() - max_age);
                    last_free = now() - max_age;
                }
            }
        }).unwrap();
        cfg_tracing! { tracing::info!("Spawned DataLogDaemon"); };
        DataLogDaemon {
            thread_handle: Some(thread_handle),
            sender: DataLogDaemonSender {
                closed: false,
                sender,
            },
            receiver: updatee,
            summary: summary_updatee
        }
    }

    pub fn get_sender(&self) -> DataLogDaemonSender {
        self.sender.clone()
    }

    pub fn borrow_sender(&self) -> &DataLogDaemonSender {
        &self.sender
    }

    pub fn get_all_entries(&mut self) -> Vec<DatalogEntryResponse> {
        self.receiver.latest().clone()
    }

    pub fn is_alive(&self) -> bool {
        self.thread_handle.is_some()
    }

    pub fn kill(&mut self) {
        cfg_tracing! { tracing::info!("Killed DataLogDaemon"); };
        drop(self.thread_handle.take());
    }

    pub fn summary(&mut self) -> HashMap<EntryName, EntryType> {
        self.summary.latest().clone()
    }
}

impl Drop for DataLogDaemon {
    fn drop(&mut self) {
        self.kill();
    }
}
