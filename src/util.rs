#![allow(dead_code)]

use crate::error::Error;

#[derive(Debug, Clone, Copy)]
pub enum UInts {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    U128(u128),
}
impl UInts {
    #[inline(always)]
    pub fn get_min_size(&self) -> UInts {
        match self {
            UInts::U8(int) => UInts::U8(*int),
            UInts::U16(int) => {
                if *int <= u8::MAX as u16 {
                    UInts::U8(*int as u8)
                } else {
                    UInts::U16(*int)
                }
            }
            UInts::U32(int) => {
                if *int <= u8::MAX as u32 {
                    UInts::U8(*int as u8)
                } else if *int <= u16::MAX as u32 {
                    UInts::U16(*int as u16)
                } else {
                    UInts::U32(*int)
                }
            }
            UInts::U64(int) => {
                if *int <= u8::MAX as u64 {
                    UInts::U8(*int as u8)
                } else if *int <= u16::MAX as u64 {
                    UInts::U16(*int as u16)
                } else if *int <= u32::MAX as u64 {
                    UInts::U32(*int as u32)
                } else {
                    UInts::U64(*int)
                }
            }
            UInts::U128(int) => {
                if *int <= u8::MAX as u128 {
                    UInts::U8(*int as u8)
                } else if *int <= u16::MAX as u128 {
                    UInts::U16(*int as u16)
                } else if *int <= u32::MAX as u128 {
                    UInts::U32(*int as u32)
                } else if *int <= u64::MAX as u128 {
                    UInts::U64(*int as u64)
                } else {
                    UInts::U128(*int)
                }
            }
        }
    }

    pub fn get_byte_count(&self) -> usize {
        match self {
            UInts::U8(_) => 1,
            UInts::U16(_) => 2,
            UInts::U32(_) => 4,
            UInts::U64(_) => 8,
            UInts::U128(_) => 16,
        }
    }

    #[inline(always)]
    pub fn to_binary(&self) -> Vec<u8> {
        //use little endian
        match self {
            UInts::U8(int) => int.to_le_bytes().to_vec(),
            UInts::U16(int) => int.to_le_bytes().to_vec(),
            UInts::U32(int) => int.to_le_bytes().to_vec(),
            UInts::U64(int) => int.to_le_bytes().to_vec(),
            UInts::U128(int) => int.to_le_bytes().to_vec(),
        }
    }

    #[inline(always)]
    pub fn from_binary(le_bytes: &[u8]) -> Self {
        match le_bytes.len() {
            1 => UInts::U8(u8::from_le_bytes(le_bytes.try_into().unwrap())),
            2 => UInts::U16(u16::from_le_bytes(le_bytes.try_into().unwrap())),
            4 => UInts::U32(u32::from_le_bytes(le_bytes.try_into().unwrap())),
            8 => UInts::U64(u64::from_le_bytes(le_bytes.try_into().unwrap())),
            16 => UInts::U128(u128::from_le_bytes(le_bytes.try_into().unwrap())),
            _ => panic!("Invalid byte length"),
        }
    }
}

impl From<u8> for UInts {
    #[inline(always)]
    fn from(int: u8) -> Self {
        UInts::U8(int)
    }
}

impl From<UInts> for u8 {
    #[inline(always)]
    fn from(int: UInts) -> Self {
        match int {
            UInts::U8(int) => int,
            UInts::U16(int) => {
                if int > u8::MAX as u16 {
                    panic!("Invalid conversion")
                } else {
                    int as u8
                }
            }
            UInts::U32(int) => {
                if int > u8::MAX as u32 {
                    panic!("Invalid conversion")
                } else {
                    int as u8
                }
            }
            UInts::U64(int) => {
                if int > u8::MAX as u64 {
                    panic!("Invalid conversion")
                } else {
                    int as u8
                }
            }
            UInts::U128(int) => {
                if int > u8::MAX as u128 {
                    panic!("Invalid conversion")
                } else {
                    int as u8
                }
            }
        }
    }
}

impl From<u16> for UInts {
    #[inline(always)]
    fn from(int: u16) -> Self {
        UInts::U16(int)
    }
}

impl From<UInts> for u16 {
    #[inline(always)]
    fn from(int: UInts) -> Self {
        match int {
            UInts::U8(int) => int as u16,
            UInts::U16(int) => int,
            UInts::U32(int) => {
                if int > u16::MAX as u32 {
                    panic!("Invalid conversion")
                } else {
                    int as u16
                }
            }
            UInts::U64(int) => {
                if int > u16::MAX as u64 {
                    panic!("Invalid conversion")
                } else {
                    int as u16
                }
            }
            UInts::U128(int) => {
                if int > u16::MAX as u128 {
                    panic!("Invalid conversion")
                } else {
                    int as u16
                }
            }
        }
    }
}

impl From<u32> for UInts {
    #[inline(always)]
    fn from(int: u32) -> Self {
        UInts::U32(int)
    }
}

impl From<UInts> for u32 {
    #[inline(always)]
    fn from(int: UInts) -> Self {
        match int {
            UInts::U8(int) => int as u32,
            UInts::U16(int) => int as u32,
            UInts::U32(int) => int,
            UInts::U64(int) => {
                if int > u32::MAX as u64 {
                    panic!("Invalid conversion")
                } else {
                    int as u32
                }
            }
            UInts::U128(int) => {
                if int > u32::MAX as u128 {
                    panic!("Invalid conversion")
                } else {
                    int as u32
                }
            }
        }
    }
}

impl From<u64> for UInts {
    #[inline(always)]
    fn from(int: u64) -> Self {
        UInts::U64(int)
    }
}

impl From<UInts> for u64 {
    #[inline(always)]
    fn from(int: UInts) -> Self {
        match int {
            UInts::U8(int) => int as u64,
            UInts::U16(int) => int as u64,
            UInts::U32(int) => int as u64,
            UInts::U64(int) => int,
            UInts::U128(int) => {
                if int > u64::MAX as u128 {
                    panic!("Invalid conversion")
                } else {
                    int as u64
                }
            }
        }
    }
}

impl From<u128> for UInts {
    #[inline(always)]
    fn from(int: u128) -> Self {
        UInts::U128(int)
    }
}

impl From<UInts> for u128 {
    #[inline(always)]
    fn from(int: UInts) -> Self {
        match int {
            UInts::U8(int) => int as u128,
            UInts::U16(int) => int as u128,
            UInts::U32(int) => int as u128,
            UInts::U64(int) => int as u128,
            UInts::U128(int) => int,
        }
    }
}

#[derive(Debug)]
pub struct RecordByteReader {
    bytes: Vec<u8>,
    index: usize,
}
impl RecordByteReader {
    #[inline]
    pub fn new(bytes: Vec<u8>) -> Self {
        RecordByteReader { bytes, index: 0 }
    }

    #[inline]
    pub fn u32(&mut self) -> Result<u32, Error> {
        if self.bytes_left() < 4 {
            return Err(Error::RecordReaderOutOfBounds);
        }
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&self.bytes[self.index..self.index + 4]);
        self.index += 4;
        Ok(u32::from_le_bytes(bytes))
    }

    #[inline]
    pub fn u64(&mut self) -> Result<u64, Error> {
        if self.bytes_left() < 8 {
            return Err(Error::RecordReaderOutOfBounds);
        }
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.bytes[self.index..self.index + 8]);
        self.index += 8;
        Ok(u64::from_le_bytes(bytes))
    }

    #[inline]
    pub fn i64(&mut self) -> Result<i64, Error> {
        if self.bytes_left() < 8 {
            panic!("RecordReaderOutOfBounds");
        }
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.bytes[self.index..self.index + 8]);
        self.index += 8;
        Ok(i64::from_le_bytes(bytes))
    }

    #[inline]
    pub fn bool(&mut self) -> Result<bool, Error> {
        if self.bytes_left() < 1 {
            return Err(Error::RecordReaderOutOfBounds);
        }
        let mut bytes = [0u8; 1];
        bytes.copy_from_slice(&self.bytes[self.index..self.index + 1]);
        self.index += 1;
        Ok(u8::from_le_bytes(bytes) != 0)
    }

    #[inline]
    pub fn u8(&mut self) -> Result<u8, Error> {
        if self.bytes_left() < 1 {
            return Err(Error::RecordReaderOutOfBounds);
        }
        let mut bytes = [0u8; 1];
        bytes.copy_from_slice(&self.bytes[self.index..self.index + 1]);
        self.index += 1;
        Ok(u8::from_le_bytes(bytes))
    }

    #[inline]
    pub fn string(&mut self, len: usize) -> Result<String, Error> {
        if self.bytes_left() < len {
            return Err(Error::RecordReaderOutOfBounds);
        }
        let mut bytes = vec![0u8; len];
        bytes.copy_from_slice(&self.bytes[self.index..self.index + len]);
        self.index += len;
        Ok(String::from_utf8(bytes).unwrap())
    }

    #[inline]
    pub fn f32(&mut self) -> Result<f32, Error> {
        if self.bytes_left() < 4 {
            return Err(Error::RecordReaderOutOfBounds);
        }
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&self.bytes[self.index..self.index + 4]);
        self.index += 4;
        Ok(f32::from_le_bytes(bytes))
    }

    #[inline]
    pub fn f64(&mut self) -> Result<f64, Error> {
        if self.bytes_left() < 8 {
            return Err(Error::RecordReaderOutOfBounds);
        }
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.bytes[self.index..self.index + 8]);
        self.index += 8;
        Ok(f64::from_le_bytes(bytes))
    }

    #[inline]
    pub fn bytes(&mut self, len: usize) -> Result<Vec<u8>, Error> {
        if self.bytes_left() < len {
            return Err(Error::RecordReaderOutOfBounds);
        }
        let mut bytes = vec![0u8; len];
        bytes.copy_from_slice(&self.bytes[self.index..self.index + len]);
        self.index += len;
        Ok(bytes)
    }

    #[inline]
    pub fn skip(&mut self, len: usize) -> Result<(), Error> {
        if self.bytes_left() < len {
            return Err(Error::RecordReaderOutOfBounds);
        }
        self.index += len;
        Ok(())
    }

    #[inline]
    pub fn the_rest(&mut self) -> Vec<u8> {
        let rest = self.bytes[self.index..].to_vec();
        self.index = self.bytes.len();
        rest
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.index == self.bytes.len()
    }

    #[inline]
    pub fn bytes_left(&self) -> usize {
        self.bytes.len() - self.index
    }

    #[inline]
    pub fn index(&self) -> usize {
        self.index
    }

    #[inline]
    pub fn total_len(&self) -> usize {
        self.bytes.len()
    }
}
