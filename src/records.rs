#![allow(dead_code)]

use frc_value::FrcValue;

use crate::{
    error::{log_result, DatalogError},
    util::{RecordByteReader, UInts},
    EntryId, EntryMetadata, EntryName, EntryType, EntryTypeMap, LeByte, LeBytes, WpiTimestamp,
};

const SUPPORTED_TYPES: [&str; 11] = [
    "raw",
    "boolean",
    "double",
    "float",
    "int64",
    "string",
    "boolean[]",
    "double[]",
    "float[]",
    "int64[]",
    "string[]",
];

fn le_bytes(s: &String) -> LeBytes {
    //is little endian processor
    if cfg!(target_endian = "little") {
        s.clone().into_bytes()
    } else {
        s.clone()
            .into_bytes()
            .into_iter()
            .map(|b| b.reverse_bits())
            .collect()
    }
}

fn chunk_by_record(all_bytes: LeBytes) -> Vec<LeBytes> {
    let mut chunks = Vec::new();
    let mut reader = RecordByteReader::new(all_bytes);
    while !reader.is_empty() {
        let mut chunk = Vec::new();
        let bit_field = RecordElementBitfield::from_bits_truncate(reader.u8().unwrap());
        chunk.push(bit_field.bits());

        // let id_length = (bit_field & 0b11) + 1;
        // let payload_length = ((bit_field >> 2) & 0b11) + 1;
        // let timestamp_length = ((bit_field >> 4) & 0b111) + 1;

        let id_length = bit_field.id_length();
        let payload_length = bit_field.payload_length();
        let timestamp_length = bit_field.timestamp_length();

        if reader.bytes_left() < (id_length + timestamp_length + payload_length) as usize {
            cfg_tracing! {
                tracing::error!("Record reader was short for chunk by record");
            }
            continue;
        }

        chunk.extend(reader.bytes(id_length as usize).unwrap());
        let payload = reader.bytes(payload_length as usize).unwrap();
        chunk.extend(payload.clone());
        chunk.extend(reader.bytes(timestamp_length as usize).unwrap());
        let payload_size: u32 = UInts::from_binary(payload).into();

        if reader.bytes_left() < payload_size as usize {
            cfg_tracing! {
                tracing::error!("Record reader was short for chunk by record payload");
            }
            continue;
        }

        chunk.extend(reader.bytes(payload_size as usize).unwrap());
        chunks.push(chunk);
    }
    chunks
}

pub fn parse_records(all_bytes: LeBytes) -> Vec<Record> {
    let chunks = chunk_by_record(all_bytes);
    let mut records = Vec::new();
    let mut type_map = EntryTypeMap::new();
    for chunk in chunks {
        if let Ok(record) = log_result(Record::from_binary(chunk, &type_map)) {
            if record.is_control() {
                let opt_type = record.as_control().unwrap().get_entry_type();
                let id = record.get_id();
                if opt_type.is_some() {
                    type_map.insert(id, opt_type.unwrap().clone());
                }
            }
            records.push(record);
        }
    }
    //sort the records based on timestamp, earliest first
    records.sort_by(|a, b| a.get_timestamp().cmp(&b.get_timestamp()));
    // records.sort_by(|a, b| b.get_timestamp().cmp(&a.get_timestamp()));
    records
}


bitflags! {
    /// The header length bitfield encodes the length of each header field as follows (starting from the least significant bit):
    /// 2-bit entry ID length (00 = 1 byte, 01 = 2 bytes, 10 = 3 bytes, 11 = 4 bytes)
    /// 2-bit payload size length (00 = 1 byte, to 11 = 4 bytes)
    /// 3-bit timestamp length (000 = 1 byte, to 111 = 8 bytes)
    /// 1-bit spare (zero)
    #[derive(Debug, Clone, Copy)]
    pub struct RecordElementBitfield: u8 {
        const ID_1 = 0b01;
        const ID_2 = 0b10;
        const ID_3 = 0b11;
        const PAYLOAD_1 = 0b0100;
        const PAYLOAD_2 = 0b1000;
        const PAYLOAD_3 = 0b1100;
        const TIMESTAMP_1 = 0b10000;
        const TIMESTAMP_2 = 0b100000;
        const TIMESTAMP_3 = 0b110000;
        const SPARE = 0b1000000;
    }
}

impl RecordElementBitfield {
    pub fn id_length(&self) -> u8 {
        match self.bits() & 0b11 {
            0b00 => 1,
            0b01 => 2,
            0b10 => 3,
            0b11 => 4,
            _ => unreachable!(),
        }
    }
    pub fn payload_length(&self) -> u8 {
        match (self.bits() >> 2) & 0b11 {
            0b00 => 1,
            0b01 => 2,
            0b10 => 3,
            0b11 => 4,
            _ => unreachable!(),
        }
    }
    pub fn timestamp_length(&self) -> u8 {
        match (self.bits() >> 4) & 0b111 {
            0b000 => 1,
            0b001 => 2,
            0b010 => 3,
            0b011 => 4,
            0b100 => 5,
            0b101 => 6,
            0b110 => 7,
            0b111 => 8,
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, Clone)]
struct RecordElementSizes {
    pub bit_field: RecordElementBitfield,
    pub timestamp: UInts,
    pub id: UInts,
    pub payload: UInts,
}
impl RecordElementSizes {
    fn create(timestamp: WpiTimestamp, id: EntryId, payload: u32) -> Self {
        let wrapped_timestamp = UInts::from(timestamp).get_min_size();
        let wrapped_id = UInts::from(id).get_min_size();
        let wrapped_payload = UInts::from(payload).get_min_size();
        // create bitfield as little endian byte
        // let bit_field = ((wrapped_id.get_byte_count() - 1) as LeByte) & 0b11
        //     | (((wrapped_payload.get_byte_count() - 1) as LeByte) & 0b11) << 2
        //     | (((wrapped_timestamp.get_byte_count() - 1) as LeByte) & 0b111) << 4;
        let bit_field = RecordElementBitfield::from_bits_truncate(
            ((wrapped_id.get_byte_count() - 1) as LeByte) & 0b11
                | (((wrapped_payload.get_byte_count() - 1) as LeByte) & 0b11) << 2
                | (((wrapped_timestamp.get_byte_count() - 1) as LeByte) & 0b111) << 4,
        );
        Self {
            bit_field,
            timestamp: wrapped_timestamp,
            id: wrapped_id,
            payload: wrapped_payload,
        }
    }
}

#[derive(Debug, Clone)]
pub enum Record {
    Data(DataRecord, WpiTimestamp, EntryId),
    Control(ControlRecord, WpiTimestamp, EntryId),
}

impl Record {
    pub fn get_timestamp(&self) -> WpiTimestamp {
        match self {
            Record::Data(_, timestamp, _) => *timestamp,
            Record::Control(_, timestamp, _) => *timestamp,
        }
    }

    pub fn get_id(&self) -> EntryId {
        match self {
            Record::Data(_, _, id) => *id,
            Record::Control(_, _, id) => *id,
        }
    }

    pub fn is_data(&self) -> bool {
        match self {
            Record::Data(_, _, _) => true,
            Record::Control(_, _, _) => false,
        }
    }

    pub fn is_control(&self) -> bool {
        match self {
            Record::Data(_, _, _) => false,
            Record::Control(_, _, _) => true,
        }
    }

    pub fn as_data(&self) -> Option<&DataRecord> {
        match self {
            Record::Data(data, _, _) => Some(data),
            Record::Control(_, _, _) => None,
        }
    }

    pub fn as_control(&self) -> Option<&ControlRecord> {
        match self {
            Record::Data(_, _, _) => None,
            Record::Control(control, _, _) => Some(control),
        }
    }

    pub fn to_binary(&self) -> LeBytes {
        match self {
            Record::Data(data, timestamp, id) => data.to_binary(*timestamp, *id),
            Record::Control(control, timestamp, id) => control.to_binary(*timestamp, *id),
        }
    }

    pub fn from_binary(bytes: LeBytes, type_map: &EntryTypeMap) -> Result<Self, DatalogError> {
        let mut reader = RecordByteReader::new(bytes);
        let bit_field = reader.u8().unwrap();

        let id_length = (bit_field & 0b11) + 1;
        let payload_length = ((bit_field >> 2) & 0b11) + 1;
        let timestamp_length = ((bit_field >> 4) & 0b111) + 1;

        let id;
        if let Ok(bin_int) = reader.bytes(id_length as usize) {
            id = UInts::from_binary(bin_int);
        } else {
            return Err(DatalogError::RecordReaderOutOfBounds("Entry id"));
        }

        if let Err(err) = reader.skip(payload_length as usize) {
            return Err(err);
        }

        let timestamp;
        if let Ok(bin_int) = reader.bytes(timestamp_length as usize) {
            timestamp = UInts::from_binary(bin_int);
        } else {
            return Err(DatalogError::RecordReaderOutOfBounds("Timestamp"));
        }

        let mut type_str = type_map
            .get(&u32::from(id))
            .unwrap_or(&"unknown".to_string())
            .clone();

        let is_control = u32::from(id) == 0u32;

        if !SUPPORTED_TYPES.contains(&type_str.as_str()) && !is_control {
            // return Err(DatalogError::RecordType(
            //     "Unsupported type: ".to_string() + &type_str,
            // ));
            type_str = "raw".to_string();
        }

        let record_payload = reader.the_rest();
        if is_control {
            if let Ok(control_record) = log_result(ControlRecord::from_binary(record_payload)) {
                cfg_tracing! { tracing::debug!("Deserialized control record"); };
                Ok(Record::Control(
                    control_record.0,
                    timestamp.into(),
                    control_record.1,
                ))
            } else {
                cfg_tracing! { tracing::warn!("Unsupported control record"); };
                Err(DatalogError::RecordDeserialize(
                    "Unsupported control record".to_string(),
                ))
            }
        } else {
            if let Ok(data_record) = log_result(DataRecord::from_binary(record_payload, type_str)) {
                cfg_tracing! { tracing::debug!("Deserialized data record"); };
                Ok(Record::Data(data_record, timestamp.into(), id.into()))
            } else {
                cfg_tracing! { tracing::warn!("Unsupported data record"); };
                Err(DatalogError::RecordDeserialize(
                    "Unsupported data record".to_string(),
                ))
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum ControlRecord {
    Start(EntryName, EntryType, EntryMetadata),
    Finish,
    Metadata(EntryMetadata),
}

impl ControlRecord {
    pub fn get_control_type(&self) -> u8 {
        match self {
            ControlRecord::Start(_, _, _) => 0,
            ControlRecord::Finish => 1,
            ControlRecord::Metadata(_) => 2,
        }
    }

    pub fn is_start(&self) -> bool {
        match self {
            ControlRecord::Start(_, _, _) => true,
            ControlRecord::Finish => false,
            ControlRecord::Metadata(_) => false,
        }
    }

    pub fn get_entry_name(&self) -> Option<&EntryName> {
        match self {
            ControlRecord::Start(name, _, _) => Some(name),
            ControlRecord::Finish => None,
            ControlRecord::Metadata(_) => None,
        }
    }

    pub fn get_entry_type(&self) -> Option<&EntryType> {
        match self {
            ControlRecord::Start(_, entry_type, _) => Some(entry_type),
            ControlRecord::Finish => None,
            ControlRecord::Metadata(_) => None,
        }
    }

    pub fn get_entry_metadata(&self) -> Option<&EntryMetadata> {
        match self {
            ControlRecord::Start(_, _, entry_metadata) => Some(entry_metadata),
            ControlRecord::Finish => None,
            ControlRecord::Metadata(entry_metadata) => Some(entry_metadata),
        }
    }
    pub fn to_binary(&self, timestamp: WpiTimestamp, id: EntryId) -> LeBytes {
        match self {
            ControlRecord::Start(name, entry_type, entry_metadata) => {
                let payload_len = 17 + name.len() + entry_type.len() + entry_metadata.len();

                let element_sizes = RecordElementSizes::create(timestamp, 0, payload_len as u32);

                let mut bytes = Vec::new();
                bytes.push(element_sizes.bit_field.bits()); //1-byte header length bitfield
                bytes.push(0u8); //1 to 4-byte (32-bit) entry ID (0 int for control records)
                bytes.extend(element_sizes.payload.to_binary()); // 1 to 4-byte (32-bit) payload size (in bytes)
                bytes.extend(element_sizes.timestamp.to_binary()); // 1 to 8-byte (64-bit) timestamp (in microseconds)
                bytes.push(self.get_control_type()); // 1-byte control record type (0 for Start control records)
                bytes.extend_from_slice(&id.to_le_bytes()); // 4-byte (32-bit) entry ID of entry being started
                bytes.extend_from_slice(&(name.len() as u32).to_le_bytes()); // 4-byte (32-bit) length of entry name string
                bytes.extend_from_slice(&le_bytes(name).as_slice()); // UTF-8 encoded entry name string
                bytes.extend_from_slice(&(entry_type.len() as u32).to_le_bytes()); // 4-byte (32-bit) length of entry type string
                bytes.extend_from_slice(&le_bytes(entry_type).as_slice()); // UTF-8 encoded entry type string
                bytes.extend_from_slice(&(entry_metadata.len() as u32).to_le_bytes()); // 4-byte (32-bit) length of entry metadata string
                bytes.extend_from_slice(&le_bytes(entry_metadata).as_slice()); // UTF-8 encoded entry metadata string
                bytes
            }
            ControlRecord::Finish => {
                let payload_len = 5u32;

                let element_sizes = RecordElementSizes::create(timestamp, 0, payload_len);

                let mut bytes = Vec::new();
                bytes.push(element_sizes.bit_field.bits()); //1-byte header length bitfield
                bytes.push(0u8); //1 to 4-byte (32-bit) entry ID (0 int for control records)
                bytes.extend(element_sizes.payload.to_binary()); // 1 to 4-byte (32-bit) payload size (in bytes)
                bytes.extend(element_sizes.timestamp.to_binary()); // 1 to 8-byte (64-bit) timestamp (in microseconds)
                bytes.push(self.get_control_type()); // 1-byte control record type (1 for Finish control records)
                bytes.extend_from_slice(&id.to_le_bytes()); // 4-byte (32-bit) entry ID of entry being finished
                bytes
            }
            ControlRecord::Metadata(entry_metadata) => {
                let payload_len = 9 + entry_metadata.len();

                let element_sizes = RecordElementSizes::create(timestamp, 0, payload_len as u32);

                let mut bytes = Vec::new();
                bytes.push(element_sizes.bit_field.bits()); //1-byte header length bitfield
                bytes.push(0u8); //1 to 4-byte (32-bit) entry ID (0 int for control records)
                bytes.extend(element_sizes.payload.to_binary()); // 1 to 4-byte (32-bit) payload size (in bytes)
                bytes.extend(element_sizes.timestamp.to_binary()); // 1 to 8-byte (64-bit) timestamp (in microseconds)
                bytes.push(self.get_control_type()); // 1-byte control record type (2 for Metadata control records)
                bytes.extend_from_slice(&(entry_metadata.len() as u32).to_le_bytes()); // 4-byte (32-bit) length of entry metadata string
                bytes.extend_from_slice(&id.to_le_bytes()); // 4-byte (32-bit) entry ID of entry being finished
                bytes
            }
        }
    }

    pub fn from_binary(bytes: LeBytes) -> Result<(Self, EntryId), DatalogError> {
        let mut reader = RecordByteReader::new(bytes);
        let control_type = reader.u8().unwrap();
        let entry_id = reader.u32().unwrap();
        match control_type {
            0 => {
                if let Ok(name_len) = reader.u32() {
                    //checks name bytes
                    if reader.bytes_left() < name_len as usize {
                        return Err(DatalogError::RecordReaderOutOfBounds(
                            "Start control record name",
                        ));
                    }
                    let name = reader.string(name_len as usize).unwrap();
                    if let Ok(type_len) = reader.u32() {
                        //checks type bytes
                        if reader.bytes_left() < type_len as usize {
                            return Err(DatalogError::RecordReaderOutOfBounds(
                                "Start control record type",
                            ));
                        }
                        let entry_type = reader.string(type_len as usize).unwrap();
                        if let Ok(metadata_len) = reader.u32() {
                            //checks metadata bytes
                            if reader.bytes_left() < metadata_len as usize {
                                return Err(DatalogError::RecordReaderOutOfBounds(
                                    "Start control record metadata",
                                ));
                            }
                            let entry_metadata = reader.string(metadata_len as usize).unwrap();
                            return Ok((
                                ControlRecord::Start(name, entry_type, entry_metadata),
                                entry_id,
                            ));
                        }
                    }
                }
                //one of the checks above failed
                Err(DatalogError::RecordReaderOutOfBounds(
                    "Start control record",
                ))
            }
            1 => Ok((ControlRecord::Finish, entry_id)),
            2 => {
                if let Ok(metadata_len) = reader.u32() {
                    if reader.bytes_left() != metadata_len as usize {
                        return Err(DatalogError::RecordReaderOutOfBounds(
                            "Metadata control record string",
                        ));
                    }
                    Ok((
                        ControlRecord::Metadata(reader.string(metadata_len as usize).unwrap()),
                        entry_id,
                    ))
                } else {
                    Err(DatalogError::RecordReaderOutOfBounds(
                        "Metadata control record length",
                    ))
                }
            }
            _ => unimplemented!(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum DataRecord {
    Raw(LeBytes),
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

impl DataRecord {
    pub fn get_data_type(&self) -> EntryType {
        match self {
            DataRecord::Raw(_) => "raw".to_string(),
            DataRecord::Boolean(_) => "boolean".to_string(),
            DataRecord::Integer(_) => "int64".to_string(),
            DataRecord::Float(_) => "float".to_string(),
            DataRecord::Double(_) => "double".to_string(),
            DataRecord::String(_) => "string".to_string(),
            DataRecord::BooleanArray(_) => "boolean[]".to_string(),
            DataRecord::IntegerArray(_) => "int64[]".to_string(),
            DataRecord::FloatArray(_) => "float[]".to_string(),
            DataRecord::DoubleArray(_) => "double[]".to_string(),
            DataRecord::StringArray(_) => "string[]".to_string(),
        }
    }

    pub fn matches_type(&self, e_type: &EntryType) -> bool {
        match self {
            DataRecord::Raw(_) => e_type == "raw",
            DataRecord::Boolean(_) => e_type == "boolean",
            DataRecord::Integer(_) => e_type == "int64",
            DataRecord::Float(_) => e_type == "float",
            DataRecord::Double(_) => e_type == "double",
            DataRecord::String(_) => e_type == "string",
            DataRecord::BooleanArray(_) => e_type == "boolean[]",
            DataRecord::IntegerArray(_) => e_type == "int64[]",
            DataRecord::FloatArray(_) => e_type == "float[]",
            DataRecord::DoubleArray(_) => e_type == "double[]",
            DataRecord::StringArray(_) => e_type == "string[]",
        }
    }

    pub fn to_binary(&self, timestamp: WpiTimestamp, id: EntryId) -> LeBytes {
        let inner_bytes = self.to_binary_inner();

        let element_sizes = RecordElementSizes::create(timestamp, id, inner_bytes.len() as u32);

        let mut bytes = Vec::new();
        bytes.push(element_sizes.bit_field.bits()); //1-byte header length bitfield
        bytes.extend(element_sizes.id.to_binary()); //1 to 4-byte (32-bit) entry ID
        bytes.extend(element_sizes.payload.to_binary()); // 1 to 4-byte (32-bit) payload size (in bytes)
        bytes.extend(element_sizes.timestamp.to_binary()); // 1 to 8-byte (64-bit) timestamp (in microseconds)
        bytes.extend(inner_bytes); // payload
        bytes
    }

    pub fn from_binary(bytes: LeBytes, type_str: String) -> Result<Self, DatalogError> {
        if bytes.len() < 1 {
            return Err(DatalogError::RecordReaderOutOfBounds("Bytes len is 0"));
        }
        Self::from_binary_inner(bytes, type_str)
    }

    pub fn binary_payload_size(&self) -> usize {
        self.to_binary_inner().len()
    }

    fn to_binary_inner(&self) -> LeBytes {
        match self {
            DataRecord::Raw(data) => data.clone(),
            DataRecord::Boolean(data) => {
                let mut bytes = Vec::new();
                bytes.push(*data as u8);
                bytes
            }
            DataRecord::Integer(data) => {
                let mut bytes = Vec::new();
                bytes.extend_from_slice(&data.to_le_bytes());
                bytes
            }
            DataRecord::Float(data) => {
                let mut bytes = Vec::new();
                bytes.extend_from_slice(&data.to_le_bytes());
                bytes
            }
            DataRecord::Double(data) => {
                let mut bytes = Vec::new();
                bytes.extend_from_slice(&data.to_le_bytes());
                bytes
            }
            DataRecord::String(data) => {
                let mut bytes = Vec::new();
                bytes.extend_from_slice(&le_bytes(&data).as_slice());
                bytes
            }
            DataRecord::BooleanArray(data) => {
                let mut bytes = Vec::new();
                for b in data {
                    bytes.push(*b as u8);
                }
                bytes
            }
            DataRecord::IntegerArray(data) => {
                let mut bytes = Vec::new();
                for i in data {
                    bytes.extend_from_slice(&i.to_le_bytes());
                }
                bytes
            }
            DataRecord::FloatArray(data) => {
                let mut bytes = Vec::new();
                for f in data {
                    bytes.extend_from_slice(&f.to_le_bytes());
                }
                bytes
            }
            DataRecord::DoubleArray(data) => {
                let mut bytes = Vec::new();
                for d in data {
                    bytes.extend_from_slice(&d.to_le_bytes());
                }
                bytes
            }
            DataRecord::StringArray(data) => {
                let mut bytes = Vec::new();
                for s in data {
                    let len = s.len() as u32;
                    bytes.extend_from_slice(&len.to_le_bytes());
                    bytes.extend_from_slice(&le_bytes(s).as_slice());
                }
                bytes
            }
        }
    }

    fn from_binary_inner(bytes: LeBytes, type_str: String) -> Result<Self, DatalogError> {
        let mut reader = RecordByteReader::new(bytes);
        match type_str.as_str() {
            "raw" => Ok(DataRecord::Raw(reader.the_rest())),
            "boolean" => {
                let b = reader.bool()?;
                Ok(DataRecord::Boolean(b))
            }
            "int64" => {
                if let Ok(i) = reader.i64() {
                    Ok(DataRecord::Integer(i))
                } else {
                    Err(DatalogError::RecordReaderOutOfBounds("Int64"))
                }
            }
            "float" => {
                if let Ok(f) = reader.f32() {
                    Ok(DataRecord::Float(f))
                } else {
                    Err(DatalogError::RecordReaderOutOfBounds("Float"))
                }
            }
            "double" => {
                if let Ok(d) = reader.f64() {
                    Ok(DataRecord::Double(d))
                } else {
                    Err(DatalogError::RecordReaderOutOfBounds("Double"))
                }
            }
            "string" => {
                if let Ok(s) = reader.string(reader.bytes_left()) {
                    Ok(DataRecord::String(s))
                } else {
                    Err(DatalogError::RecordReaderOutOfBounds("String"))
                }
            }
            "boolean[]" => {
                let mut bools = Vec::new();
                while !reader.is_empty() {
                    bools.push(reader.bool().unwrap());
                }
                Ok(DataRecord::BooleanArray(bools))
            }
            "int64[]" => {
                let mut ints = Vec::new();
                while reader.bytes_left() >= 8 {
                    ints.push(reader.i64().unwrap());
                }
                Ok(DataRecord::IntegerArray(ints))
            }
            "float[]" => {
                let mut floats = Vec::new();
                while reader.bytes_left() >= 4 {
                    floats.push(reader.f32().unwrap());
                }
                Ok(DataRecord::FloatArray(floats))
            }
            "double[]" => {
                let mut doubles = Vec::new();
                while reader.bytes_left() >= 8 {
                    doubles.push(reader.f64().unwrap());
                }
                Ok(DataRecord::DoubleArray(doubles))
            }
            "string[]" => {
                let mut strings = Vec::new();
                while reader.bytes_left() >= 4 {
                    let len = reader.u32().unwrap();
                    if reader.bytes_left() < len as usize {
                        return Err(DatalogError::RecordReaderOutOfBounds("String[]"));
                    }
                    strings.push(reader.string(len as usize).unwrap());
                }
                Ok(DataRecord::StringArray(strings))
            }
            _ => Err(DatalogError::RecordType(type_str)),
        }
    }
}

impl From<DataRecord> for FrcValue {
    fn from(record: DataRecord) -> Self {
        match record {
            DataRecord::Raw(data) => FrcValue::Binary(frc_value::FrcBinaryFormats::Raw(data)),
            DataRecord::Boolean(data) => FrcValue::Boolean(data),
            DataRecord::Integer(data) => FrcValue::Int(data),
            DataRecord::Float(data) => FrcValue::Float(data),
            DataRecord::Double(data) => FrcValue::Double(data),
            DataRecord::String(data) => FrcValue::String(data),
            DataRecord::BooleanArray(data) => FrcValue::BooleanArray(data),
            DataRecord::IntegerArray(data) => FrcValue::IntArray(data),
            DataRecord::FloatArray(data) => FrcValue::FloatArray(data),
            DataRecord::DoubleArray(data) => FrcValue::DoubleArray(data),
            DataRecord::StringArray(data) => FrcValue::StringArray(data),
        }
    }
}

impl From<FrcValue> for DataRecord {
    fn from(value: FrcValue) -> Self {
        match value {
            FrcValue::Binary(data) => match data {
                frc_value::FrcBinaryFormats::Raw(data_inner) => DataRecord::Raw(data_inner),
                frc_value::FrcBinaryFormats::MsgPack(data_inner) => DataRecord::Raw(data_inner),
                frc_value::FrcBinaryFormats::Protobuf(data_inner) => DataRecord::Raw(data_inner)
            },
            FrcValue::Boolean(data) => DataRecord::Boolean(data),
            FrcValue::Int(data) => DataRecord::Integer(data),
            FrcValue::Float(data) => DataRecord::Float(data),
            FrcValue::Double(data) => DataRecord::Double(data),
            FrcValue::String(data) => DataRecord::String(data),
            FrcValue::BooleanArray(data) => DataRecord::BooleanArray(data),
            FrcValue::IntArray(data) => DataRecord::IntegerArray(data),
            FrcValue::FloatArray(data) => DataRecord::FloatArray(data),
            FrcValue::DoubleArray(data) => DataRecord::DoubleArray(data),
            FrcValue::StringArray(data) => DataRecord::StringArray(data),
        }
    }
}
