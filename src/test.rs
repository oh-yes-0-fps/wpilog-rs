use std::{path::PathBuf, collections::HashMap};

use crate::{log::{CreateDataLogConfig, DataLog, OpenDataLogConfig, IOType, DataLogValue}, util::UInts, records::{Record, DataRecord}, now};

#[test]
fn test_uint_enum() {
    let val = 10u32;
    let min_size_val = UInts::from(val).get_min_size();
    assert_eq!(min_size_val.get_byte_count(), 1);

    let bytes = UInts::from(1u8).to_binary();
    assert_eq!(bytes.len(), 1);
    assert_eq!(bytes[0], 1u8);

    let timestamp = now();
    let min_size_timestamp = UInts::from(timestamp).get_min_size();
    assert_eq!(min_size_timestamp.get_byte_count(), 8);
    assert!(timestamp < now() + 1000*1000);

    let bytes = UInts::from(timestamp).to_binary();
    assert_eq!(bytes.len(), 8);

    let decoded_timestamp = UInts::from_binary(bytes);
    assert_eq!(u64::from(decoded_timestamp), u64::from(min_size_timestamp));
}

#[test]
fn test_record_binary() {
    let timestamp = now();
    let entry_id = 2u32.pow(24);
    let timestamp_size = UInts::from(timestamp).get_min_size().get_byte_count();
    let entry_id_size = UInts::from(entry_id).get_min_size().get_byte_count();
    let record = Record::Data(DataRecord::Double(1.0), timestamp, entry_id);
    let bytes = record.to_binary();
    assert_eq!(bytes.len(),
        1 /*bit field */
        + entry_id_size
        + 1 /*payload size int */
        + timestamp_size
        + 8 /*payload (f64) */);

    let entry_type_map = HashMap::from([(entry_id, String::from("double"))]);
    let rerecord = Record::from_binary(bytes, &entry_type_map).unwrap();
    assert_eq!(rerecord.is_data(), record.is_data());
    assert_eq!(rerecord.get_id(), record.get_id());
    assert_eq!(rerecord.get_timestamp(), record.get_timestamp());
    assert_eq!(
        DataLogValue::from(rerecord.as_data().unwrap().clone()),
        DataLogValue::from(record.as_data().unwrap().clone()));
}

#[test]
fn basic_le_byte_read() {
    let val: f64 = 10.0;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&val.to_le_bytes());

    let mut new_bytes = [0u8; 8];
    new_bytes.copy_from_slice(&bytes);
    let read_val = f64::from_le_bytes(new_bytes);
    assert_eq!(read_val, val);
}

#[test]
fn test_read_and_save() {
    tracing_subscriber::fmt::init();

    let file_path = PathBuf::from("data_log.wpilog");

    DataLog::delete(file_path.clone()).ok();

    let config = CreateDataLogConfig {
        file_path: file_path.clone(),
        can_retro: false,
        metadata: String::from("owo meta data"),
    };

    let mut data_log = DataLog::create(config).unwrap();
    let entry_name = String::from("/test");
    data_log.create_entry(
        entry_name.clone(),
        String::from("double"), 
        String::from("{ metadata: true}")).unwrap();
    data_log.append_to_entry(entry_name.clone(), DataLogValue::Double(10.0)).unwrap();
    data_log.append_to_entry(entry_name.clone(), DataLogValue::Double(20.0)).unwrap();
    data_log.append_to_entry(entry_name.clone(), DataLogValue::Double(30.0)).unwrap();
    data_log.kill_entry(entry_name.clone()).unwrap();

    let last_val = data_log.get_last_entry_value(entry_name.clone()).unwrap();
    assert_eq!(last_val.value, DataLogValue::Double(30.0));

    data_log.flush().unwrap();

    //this also implicitly flushes
    drop(data_log);

    let config = OpenDataLogConfig {
        file_path: file_path.clone(),
        can_retro: false,
        io_type: IOType::ReadOnly,
    };

    let data_log = DataLog::open(config).unwrap();

    let last_val = data_log.get_last_entry_value(entry_name).unwrap();
    assert_eq!(last_val.value, DataLogValue::Double(30.0));

    DataLog::delete(file_path).unwrap();
}