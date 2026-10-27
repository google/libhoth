// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtoInputError {
    UnexpectedEof,
    VarintOverflow,
    UnsupportedWireType(u8),
}

impl fmt::Display for ProtoInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof => write!(f, "Unexpected EOF while parsing protobuf stream"),
            Self::VarintOverflow => write!(f, "Varint overflow (greater than 64 bits)"),
            Self::UnsupportedWireType(wt) => write!(f, "Unsupported protobuf wire type: {}", wt),
        }
    }
}

impl std::error::Error for ProtoInputError {}

/// Supported protobuf field types for decoding, represented as an open enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FieldType(pub i32);

#[allow(non_upper_case_globals)]
impl FieldType {
    pub const Double: FieldType = FieldType(1);
    pub const Float: FieldType = FieldType(2);
    pub const Int64: FieldType = FieldType(3);
    pub const Uint64: FieldType = FieldType(4);
    pub const Int32: FieldType = FieldType(5);
    pub const Fixed64: FieldType = FieldType(6);
    pub const Fixed32: FieldType = FieldType(7);
    pub const Bool: FieldType = FieldType(8);
    pub const String: FieldType = FieldType(9);
    pub const Group: FieldType = FieldType(10);
    pub const Message: FieldType = FieldType(11);
    pub const Bytes: FieldType = FieldType(12);
    pub const Uint32: FieldType = FieldType(13);
    pub const Enum: FieldType = FieldType(14);
    pub const Sfixed32: FieldType = FieldType(15);
    pub const Sfixed64: FieldType = FieldType(16);
    pub const Sint32: FieldType = FieldType(17);
    pub const Sint64: FieldType = FieldType(18);
}

/// A parsed protobuf wire-format record containing its typed value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record<'a> {
    Varint(u64),
    Fixed64(u64),
    LengthDelimited(&'a [u8]),
    Fixed32(u32),
}

impl<'a> Record<'a> {
    /// Returns the raw wire type u8 value of this record.
    pub fn wire_type_u8(&self) -> u8 {
        match self {
            Self::Varint(_) => 0,
            Self::Fixed64(_) => 1,
            Self::LengthDelimited(_) => 2,
            Self::Fixed32(_) => 5,
        }
    }

    /// Decodes this record's value as a `u64` according to the given `FieldType`.
    ///
    /// This method automatically handles type-specific decoding rules, including:
    /// - **Zig-zag decoding** for signed varints (`Sint32` and `Sint64`).
    /// - **Sign-extension** for signed fixed-width integers (`Sfixed32`), mapping negative
    ///   values to their correct 64-bit representation (e.g., `-1` becomes `u64::MAX`).
    ///
    /// Returns `ProtoInputError::UnsupportedWireType` if the record's wire type
    /// does not match the expected wire type for the `FieldType`.
    pub fn decode_u64(&self, field_type: FieldType) -> Result<u64, ProtoInputError> {
        match (self, field_type) {
            // Varint wire type (0)
            (
                Self::Varint(v),
                FieldType::Int64
                | FieldType::Uint64
                | FieldType::Int32
                | FieldType::Uint32
                | FieldType::Bool
                | FieldType::Enum,
            ) => Ok(*v),
            (Self::Varint(v), FieldType::Sint32 | FieldType::Sint64) => {
                Ok(decode_zigzag(*v) as u64)
            }
            // Fixed64 wire type (1)
            (Self::Fixed64(v), FieldType::Fixed64 | FieldType::Double | FieldType::Sfixed64) => {
                Ok(*v)
            }
            // Fixed32 wire type (5)
            (Self::Fixed32(v), FieldType::Fixed32 | FieldType::Float) => Ok(*v as u64),
            (Self::Fixed32(v), FieldType::Sfixed32) => Ok((*v as i32) as u64),
            _ => Err(ProtoInputError::UnsupportedWireType(self.wire_type_u8())),
        }
    }
}

/// A lightweight, FFI-free reader for parsing protobuf wire format streams.
pub struct ProtoReader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> ProtoReader<'a> {
    /// Creates a new `ProtoReader` wrapping the given byte slice.
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    /// Returns the current cursor position.
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// Set the cursor position.
    pub fn set_pos(&mut self, pos: usize) {
        self.pos = pos;
    }

    /// Returns true if the cursor has reached the end of the byte slice.
    pub fn is_eof(&self) -> bool {
        self.pos >= self.bytes.len()
    }

    /// Reads a Varint from the stream.
    fn read_varint(&mut self) -> Result<u64, ProtoInputError> {
        let mut result = 0u64;
        let mut shift = 0;
        while self.pos < self.bytes.len() {
            let byte = self.bytes[self.pos];
            self.pos += 1;
            if shift == 63 && (byte & 0x7F) > 1 {
                return Err(ProtoInputError::VarintOverflow);
            }
            result |= ((byte & 0x7F) as u64) << shift;
            if (byte & 0x80) == 0 {
                return Ok(result);
            }
            shift += 7;
            if shift >= 64 {
                return Err(ProtoInputError::VarintOverflow);
            }
        }
        Err(ProtoInputError::UnexpectedEof)
    }

    /// Reads a raw slice of bytes of the specified length.
    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], ProtoInputError> {
        if len <= self.bytes.len() - self.pos {
            let slice = &self.bytes[self.pos..self.pos + len];
            self.pos += len;
            Ok(slice)
        } else {
            Err(ProtoInputError::UnexpectedEof)
        }
    }

    /// Reads a length-delimited payload.
    fn read_length_delimited(&mut self) -> Result<&'a [u8], ProtoInputError> {
        let len_u64 = self.read_varint()?;
        let len = usize::try_from(len_u64).map_err(|_| ProtoInputError::UnexpectedEof)?;
        self.read_bytes(len)
    }

    /// Reads the next tag and parses its value, returning the field number and the record data.
    ///
    /// This guarantees the reader is always advanced to the start of the next field.
    pub fn read_record(&mut self) -> Result<(u32, Record<'a>), ProtoInputError> {
        let tag = self.read_varint()?;
        let field_number = (tag >> 3) as u32;
        let wire_type = (tag & 0x7) as u8;

        let record = match wire_type {
            0 => {
                let val = self.read_varint()?;
                Record::Varint(val)
            }
            1 => {
                let bytes = self.read_bytes(8)?;
                let mut b = [0u8; 8];
                b.copy_from_slice(bytes);
                Record::Fixed64(u64::from_le_bytes(b))
            }
            2 => {
                let bytes = self.read_length_delimited()?;
                Record::LengthDelimited(bytes)
            }
            5 => {
                let bytes = self.read_bytes(4)?;
                let mut b = [0u8; 4];
                b.copy_from_slice(bytes);
                Record::Fixed32(u32::from_le_bytes(b))
            }
            other => return Err(ProtoInputError::UnsupportedWireType(other)),
        };

        Ok((field_number, record))
    }

    /// Scans the stream from the current position to find a field by its number.
    /// Does not advance the caller's cursor.
    pub fn find_field(&self, target_number: u32) -> Option<Record<'a>> {
        let mut reader = ProtoReader::new(self.bytes);
        reader.pos = self.pos;
        let mut last_match = None;
        while !reader.is_eof() {
            if let Ok((field_number, record)) = reader.read_record() {
                if field_number == target_number {
                    last_match = Some(record);
                }
            } else {
                return None;
            }
        }
        last_match
    }
}

/// Decodes a 64-bit zig-zag encoded value back to a signed 64-bit integer.
pub fn decode_zigzag(val: u64) -> i64 {
    ((val >> 1) as i64) ^ -((val & 1) as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_varint_valid() {
        // 0
        let mut reader = ProtoReader::new(&[0x00]);
        assert_eq!(reader.read_varint().unwrap(), 0);

        // 127
        let mut reader = ProtoReader::new(&[0x7F]);
        assert_eq!(reader.read_varint().unwrap(), 127);

        // 128
        let mut reader = ProtoReader::new(&[0x80, 0x01]);
        assert_eq!(reader.read_varint().unwrap(), 128);

        // Max u64: 10 bytes: 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01
        let mut reader =
            ProtoReader::new(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01]);
        assert_eq!(reader.read_varint().unwrap(), u64::MAX);
    }

    #[test]
    fn test_read_varint_overflow() {
        // 10th byte has bit 1 set (represents value > 64 bits)
        let mut reader =
            ProtoReader::new(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02]);
        assert_eq!(
            reader.read_varint().unwrap_err(),
            ProtoInputError::VarintOverflow
        );

        // 11th byte present
        let mut reader = ProtoReader::new(&[
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01,
        ]);
        assert_eq!(
            reader.read_varint().unwrap_err(),
            ProtoInputError::VarintOverflow
        );
    }

    #[test]
    fn test_decode_zigzag() {
        assert_eq!(decode_zigzag(0), 0);
        assert_eq!(decode_zigzag(1), -1);
        assert_eq!(decode_zigzag(2), 1);
        assert_eq!(decode_zigzag(3), -2);
        assert_eq!(decode_zigzag(4), 2);
        assert_eq!(decode_zigzag(4294967294), 2147483647);
        assert_eq!(decode_zigzag(4294967295), -2147483648);
        assert_eq!(decode_zigzag(u64::MAX), i64::MIN);
        assert_eq!(decode_zigzag(u64::MAX - 1), i64::MAX);
    }

    #[test]
    fn test_record_wire_type_u8() {
        assert_eq!(Record::Varint(100).wire_type_u8(), 0);
        assert_eq!(Record::Fixed64(0).wire_type_u8(), 1);
        assert_eq!(Record::LengthDelimited(&[]).wire_type_u8(), 2);
        assert_eq!(Record::Fixed32(0).wire_type_u8(), 5);
    }

    #[test]
    fn test_proto_reader_basic() {
        let bytes = &[1, 2, 3, 4];
        let mut reader = ProtoReader::new(bytes);
        assert_eq!(reader.pos(), 0);
        assert!(!reader.is_eof());

        reader.set_pos(2);
        assert_eq!(reader.pos(), 2);
        assert!(!reader.is_eof());

        reader.set_pos(4);
        assert_eq!(reader.pos(), 4);
        assert!(reader.is_eof());

        reader.set_pos(5);
        assert_eq!(reader.pos(), 5);
        assert!(reader.is_eof());
    }

    #[test]
    fn test_proto_input_error_display() {
        assert_eq!(
            format!("{}", ProtoInputError::UnexpectedEof),
            "Unexpected EOF while parsing protobuf stream"
        );
        assert_eq!(
            format!("{}", ProtoInputError::VarintOverflow),
            "Varint overflow (greater than 64 bits)"
        );
        assert_eq!(
            format!("{}", ProtoInputError::UnsupportedWireType(3)),
            "Unsupported protobuf wire type: 3"
        );
    }

    #[test]
    fn test_read_record_varint() {
        // Field 1, WireType 0 (Varint), Value 150
        // tag = (1 << 3) | 0 = 8 (0x08)
        // value = 150 -> 0x96, 0x01
        let bytes = &[0x08, 0x96, 0x01];
        let mut reader = ProtoReader::new(bytes);
        let (field, record) = reader.read_record().unwrap();
        assert_eq!(field, 1);
        assert_eq!(record, Record::Varint(150));
        assert!(reader.is_eof());
    }

    #[test]
    fn test_read_record_fixed64() {
        // Field 2, WireType 1 (Fixed64), Value [1, 2, 3, 4, 5, 6, 7, 8]
        // tag = (2 << 3) | 1 = 17 (0x11)
        let bytes = &[0x11, 1, 2, 3, 4, 5, 6, 7, 8];
        let mut reader = ProtoReader::new(bytes);
        let (field, record) = reader.read_record().unwrap();
        assert_eq!(field, 2);
        assert_eq!(record, Record::Fixed64(0x0807060504030201));
        assert!(reader.is_eof());
    }

    #[test]
    fn test_read_record_length_delimited() {
        // Field 3, WireType 2 (LengthDelimited), Value "hello" (5 bytes)
        // tag = (3 << 3) | 2 = 26 (0x1A)
        // length = 5
        let bytes = &[0x1A, 0x05, b'h', b'e', b'l', b'l', b'o'];
        let mut reader = ProtoReader::new(bytes);
        let (field, record) = reader.read_record().unwrap();
        assert_eq!(field, 3);
        assert_eq!(record, Record::LengthDelimited(b"hello"));
        assert!(reader.is_eof());
    }

    #[test]
    fn test_read_record_fixed32() {
        // Field 4, WireType 5 (Fixed32), Value [9, 10, 11, 12]
        // tag = (4 << 3) | 5 = 37 (0x25)
        let bytes = &[0x25, 9, 10, 11, 12];
        let mut reader = ProtoReader::new(bytes);
        let (field, record) = reader.read_record().unwrap();
        assert_eq!(field, 4);
        assert_eq!(record, Record::Fixed32(0x0C0B0A09));
        assert!(reader.is_eof());
    }

    #[test]
    fn test_read_record_errors() {
        // Unexpected EOF on tag (empty)
        let mut reader = ProtoReader::new(&[]);
        assert_eq!(
            reader.read_record().unwrap_err(),
            ProtoInputError::UnexpectedEof
        );

        // Unexpected EOF on tag (partial varint)
        let mut reader = ProtoReader::new(&[0x80]);
        assert_eq!(
            reader.read_record().unwrap_err(),
            ProtoInputError::UnexpectedEof
        );

        // Varint overflow on tag
        let mut reader =
            ProtoReader::new(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02]);
        assert_eq!(
            reader.read_record().unwrap_err(),
            ProtoInputError::VarintOverflow
        );

        // Unsupported wire type (Type 3)
        // tag = (1 << 3) | 3 = 11 (0x0B)
        let mut reader = ProtoReader::new(&[0x0B]);
        assert_eq!(
            reader.read_record().unwrap_err(),
            ProtoInputError::UnsupportedWireType(3)
        );

        // Unexpected EOF on Varint value
        // tag = 8 (field 1, varint), value starts but EOFs
        let mut reader = ProtoReader::new(&[0x08, 0x80]);
        assert_eq!(
            reader.read_record().unwrap_err(),
            ProtoInputError::UnexpectedEof
        );

        // Unexpected EOF on Fixed64 value
        // tag = 17 (field 2, fixed64), but only 7 bytes follow
        let mut reader = ProtoReader::new(&[0x11, 1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(
            reader.read_record().unwrap_err(),
            ProtoInputError::UnexpectedEof
        );

        // Unexpected EOF on LengthDelimited length (partial varint)
        // tag = 26 (field 3, length delimited)
        let mut reader = ProtoReader::new(&[0x1A, 0x80]);
        assert_eq!(
            reader.read_record().unwrap_err(),
            ProtoInputError::UnexpectedEof
        );

        // Unexpected EOF on LengthDelimited value
        // tag = 26, length = 5, but only 4 bytes follow
        let mut reader = ProtoReader::new(&[0x1A, 0x05, b'h', b'e', b'l', b'l']);
        assert_eq!(
            reader.read_record().unwrap_err(),
            ProtoInputError::UnexpectedEof
        );

        // Unexpected EOF on Fixed32 value
        // tag = 37 (field 4, fixed32), but only 3 bytes follow
        let mut reader = ProtoReader::new(&[0x25, 9, 10, 11]);
        assert_eq!(
            reader.read_record().unwrap_err(),
            ProtoInputError::UnexpectedEof
        );
    }

    #[test]
    fn test_find_field() {
        // Stream:
        // Field 1: Varint 150 -> [0x08, 0x96, 0x01]
        // Field 2: LengthDelimited "hello" -> [0x12, 0x05, b'h', b'e', b'l', b'l', b'o']
        // Field 3: Fixed32 [9, 10, 11, 12] -> [0x1D, 9, 10, 11, 12] (tag: (3<<3)|5 = 29 = 0x1D)
        let bytes = &[
            0x08, 0x96, 0x01, 0x12, 0x05, b'h', b'e', b'l', b'l', b'o', 0x1D, 9, 10, 11, 12,
        ];

        let reader = ProtoReader::new(bytes);

        // Find existing fields
        assert_eq!(reader.find_field(1), Some(Record::Varint(150)));
        assert_eq!(
            reader.find_field(2),
            Some(Record::LengthDelimited(b"hello"))
        );
        assert_eq!(reader.find_field(3), Some(Record::Fixed32(0x0C0B0A09)));

        // Find non-existent field
        assert_eq!(reader.find_field(4), None);

        // Find from a advanced position
        let mut mut_reader = ProtoReader::new(bytes);
        mut_reader.read_record().unwrap(); // consumes Field 1
        assert_eq!(mut_reader.pos(), 3);

        // find_field on mut_reader should start scanning from pos=3
        assert_eq!(mut_reader.find_field(1), None); // Field 1 is in the past
        assert_eq!(
            mut_reader.find_field(2),
            Some(Record::LengthDelimited(b"hello"))
        );
        assert_eq!(mut_reader.find_field(3), Some(Record::Fixed32(0x0C0B0A09)));
    }

    #[test]
    fn test_find_field_with_corruption() {
        // Stream:
        // Field 1: Varint 150 -> [0x08, 0x96, 0x01]
        // Corrupted part: invalid tag or unexpected EOF
        let bytes_corrupted_after = &[
            0x08, 0x96, 0x01, // Field 1
            0x12, 0x05, b'h', // Corrupted Field 2 (truncated length delimited)
        ];

        let reader = ProtoReader::new(bytes_corrupted_after);
        // Since the stream is corrupted, we cannot find any fields because "last one wins"
        // requires scanning the entire stream, which will encounter the corruption.
        assert_eq!(reader.find_field(1), None);
        // We cannot find Field 2 because it's corrupted
        assert_eq!(reader.find_field(2), None);
        // We cannot find Field 3 (which is not present, and scanning hits corruption)
        assert_eq!(reader.find_field(3), None);
    }

    #[test]
    fn test_find_field_duplicate() {
        // Stream:
        // Field 1: Varint 150 -> [0x08, 0x96, 0x01]
        // Field 1: Varint 200 -> [0x08, 0xC8, 0x01]
        let bytes = &[
            0x08, 0x96, 0x01, // Field 1 (first occurrence)
            0x08, 0xC8, 0x01, // Field 1 (second occurrence)
        ];
        let reader = ProtoReader::new(bytes);
        // "Last one wins" for singular fields:
        assert_eq!(reader.find_field(1), Some(Record::Varint(200)));
    }

    #[test]
    fn test_record_decode_helpers() {
        // Varint tests
        let rec = Record::Varint(150);
        assert_eq!(rec.decode_u64(FieldType::Uint64).unwrap(), 150);
        assert_eq!(rec.decode_u64(FieldType::Int64).unwrap(), 150);

        // Sint32 / Sint64 zig-zag decoding (3 decodes to -2)
        let rec = Record::Varint(3);
        assert_eq!(rec.decode_u64(FieldType::Sint64).unwrap(), u64::MAX - 1);
        assert_eq!(rec.decode_u64(FieldType::Sint32).unwrap(), u64::MAX - 1);

        // Fixed64 tests
        let rec = Record::Fixed64(1);
        assert_eq!(rec.decode_u64(FieldType::Fixed64).unwrap(), 1);
        assert_eq!(rec.decode_u64(FieldType::Sfixed64).unwrap(), 1);

        // Sfixed64 negative tests
        let rec = Record::Fixed64(u64::MAX);
        assert_eq!(rec.decode_u64(FieldType::Sfixed64).unwrap(), u64::MAX);

        // Fixed32 tests
        let rec = Record::Fixed32(1);
        assert_eq!(rec.decode_u64(FieldType::Fixed32).unwrap(), 1);

        // Sfixed32 negative tests (u32::MAX is -1 as i32, which sign-extends to u64::MAX)
        let rec = Record::Fixed32(u32::MAX);
        assert_eq!(rec.decode_u64(FieldType::Sfixed32).unwrap(), u64::MAX);

        // Unsupported wire type mismatches
        let rec = Record::Varint(100);
        assert_eq!(
            rec.decode_u64(FieldType::Fixed32).unwrap_err(),
            ProtoInputError::UnsupportedWireType(0)
        );

        let rec = Record::Fixed32(0);
        assert_eq!(
            rec.decode_u64(FieldType::Uint32).unwrap_err(),
            ProtoInputError::UnsupportedWireType(5)
        );
    }
}
