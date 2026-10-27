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

use openprot_proto_reader::FieldType;
use openprot_proto_reader::ProtoInputError;
use openprot_proto_reader::ProtoReader;
use openprot_proto_reader::Record;
use openprot_proto_reflect::TypeExt;
use openprot_tlv::TlvFlags;
use openprot_tlv::TlvHeader;
use openprot_tlv_proto_meta::DescriptorProtoExt;
use openprot_tlv_proto_meta::DescriptorProtoTlvExt;
use openprot_tlv_proto_meta::FieldLayout;
use openprot_tlv_proto_meta::NameStrExt;
use openprot_tlv_proto_meta::TlvLayout;
use openprot_tlv_proto_meta::TlvLayoutError;
use openprot_tlv_proto_meta::Type;
use openprot_tlv_proto_meta::find_message_descriptor;
use std::fmt;
use zerocopy::IntoBytes;

// Re-export the descriptor rust proto so clients can pass it
pub use descriptor_rust_proto::FileDescriptorSet;

// Re-export DescriptorInfo so clients can easily type it
pub use ::protobuf::__internal::runtime::__unstable::DescriptorInfo;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtoConvError {
    MessageNotFound(String),
    MissingTlvFourcc(String),
    InvalidTlvFourcc(String),
    VarintDecodeError,
    UnsupportedWireType(u8),
    InvalidUtf8,
    ProtoInput(ProtoInputError),
    InvalidLayout(Box<TlvLayoutError>),
    FieldValueTooLong {
        field_name: String,
        value_len: usize,
        max_len: usize,
    },
    FieldValueOutOfRange {
        field_name: String,
        value: u64,
        bit_len: usize,
        is_signed: bool,
    },
    ByteFieldLengthMismatch {
        field_name: String,
        actual_len: usize,
        expected_len: usize,
    },
}

impl From<ProtoInputError> for ProtoConvError {
    fn from(err: ProtoInputError) -> Self {
        Self::ProtoInput(err)
    }
}

impl From<TlvLayoutError> for ProtoConvError {
    fn from(err: TlvLayoutError) -> Self {
        Self::InvalidLayout(Box::new(err))
    }
}

impl fmt::Display for ProtoConvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MessageNotFound(msg) => write!(f, "Message descriptor not found: {}", msg),
            Self::MissingTlvFourcc(msg) => {
                write!(f, "Missing tlv_fourcc option on message: {}", msg)
            }
            Self::InvalidTlvFourcc(err) => write!(f, "Invalid tlv_fourcc option: {}", err),
            Self::VarintDecodeError => {
                write!(f, "Failed to decode Varint from protobuf wire format")
            }
            Self::UnsupportedWireType(wt) => write!(f, "Unsupported protobuf wire type: {}", wt),
            Self::InvalidUtf8 => write!(f, "Invalid UTF-8 in descriptor string"),
            Self::ProtoInput(err) => write!(f, "Protobuf stream read error: {}", err),
            Self::InvalidLayout(err) => write!(f, "{}", err),
            Self::FieldValueTooLong {
                field_name,
                value_len,
                max_len,
            } => {
                write!(
                    f,
                    "Value for field '{}' is too long (length is {} bytes, but target packed size in the fixed struct is only {} bytes).",
                    field_name, value_len, max_len
                )
            }
            Self::FieldValueOutOfRange {
                field_name,
                value,
                bit_len,
                is_signed,
            } => {
                let bit_len = *bit_len;
                if *is_signed {
                    let min_value = if bit_len >= 64 {
                        i64::MIN
                    } else {
                        -(1i64 << (bit_len - 1))
                    };
                    let max_value = if bit_len >= 64 {
                        i64::MAX
                    } else {
                        (1i64 << (bit_len - 1)) - 1
                    };
                    write!(
                        f,
                        "Value {} for field '{}' is out of range for its packed bit-width of {} bits (valid range is {}..={}).",
                        *value as i64, field_name, bit_len, min_value, max_value
                    )
                } else {
                    let max_value = if bit_len >= 64 {
                        u64::MAX
                    } else {
                        (1u64 << bit_len) - 1
                    };
                    write!(
                        f,
                        "Value {} for field '{}' is out of range for its packed bit-width of {} bits (valid range is 0..={}).",
                        value, field_name, bit_len, max_value
                    )
                }
            }
            Self::ByteFieldLengthMismatch {
                field_name,
                actual_len,
                expected_len,
            } => {
                write!(
                    f,
                    "Length of bytes field '{}' must match the target size exactly (expected {} bytes, got {} bytes).",
                    field_name, expected_len, actual_len
                )
            }
        }
    }
}

impl std::error::Error for ProtoConvError {}

/// Encodes a serialized protobuf message into its packed TLV representation.
///
/// Returns a guaranteed 32-bit aligned `Vec<u32>` buffer representing the TLV data.
pub fn proto_to_tlv(
    desc_set: &FileDescriptorSet,
    message_name: &str,
    proto_bytes: &[u8],
) -> Result<Vec<u32>, ProtoConvError> {
    let msg_desc = find_message_descriptor(desc_set, message_name)
        .ok_or_else(|| ProtoConvError::MessageNotFound(message_name.to_string()))?;

    let mut out = Vec::new();
    encode_message(desc_set, msg_desc, proto_bytes, &mut out)?;
    Ok(out)
}

/// Encodes a protobuf message struct directly into its packed TLV representation,
/// using the self-contained `DescriptorInfo` generated by the protobuf compiler.
///
/// Returns a guaranteed 32-bit aligned `Vec<u32>` buffer representing the TLV data.
pub fn message_to_tlv<M: protobuf::Message>(
    info: &DescriptorInfo,
    message: &M,
) -> Result<Vec<u32>, ProtoConvError> {
    let full_type_name = std::any::type_name::<M>();

    let proto_bytes = message
        .serialize()
        .map_err(|_| ProtoConvError::VarintDecodeError)?;

    proto_to_tlv_with_info(info, full_type_name, &proto_bytes)
}

/// Encodes a serialized protobuf message into its packed TLV representation,
/// using the self-contained `DescriptorInfo` generated by the protobuf compiler.
///
/// Returns a guaranteed 32-bit aligned `Vec<u32>` buffer representing the TLV data.
pub fn proto_to_tlv_with_info(
    info: &DescriptorInfo,
    message_name: &str,
    proto_bytes: &[u8],
) -> Result<Vec<u32>, ProtoConvError> {
    let desc_set = openprot_tlv_proto_meta::collect_descriptor_set(info)
        .ok_or(ProtoConvError::VarintDecodeError)?;

    proto_to_tlv(&desc_set, message_name, proto_bytes)
}

/// Encodes a protobuf message into its packed TLV representation, including the 8-byte TLV header.
fn encode_message<'a>(
    desc_set: &'a FileDescriptorSet,
    msg_desc: descriptor_rust_proto::DescriptorProtoView<'a>,
    proto_bytes: &[u8],
    out: &mut Vec<u32>,
) -> Result<(), ProtoConvError> {
    let tag = msg_desc
        .tlv_fourcc()
        .ok_or_else(|| ProtoConvError::MissingTlvFourcc(msg_desc.name_str().to_string()))?;

    let header_len = core::mem::size_of::<TlvHeader>();
    let header_start_bytes = out.len() * 4;

    // Reserve space for the header using TlvHeader directly (2 words)
    out.resize(out.len() + 2, 0);

    let body_end_bytes = encode_message_body(
        desc_set,
        msg_desc,
        proto_bytes,
        out,
        header_start_bytes + header_len,
    )?;

    let raw_body_len = body_end_bytes - header_start_bytes - header_len;
    let padded_body_len = (raw_body_len + 3) & !3;
    let padding_bytes = (padded_body_len - raw_body_len) as u8;

    if padding_bytes > 0 {
        out.resize((header_start_bytes + header_len + padded_body_len) / 4, 0);
    }

    let word_len =
        u16::try_from(padded_body_len / 4).map_err(|_| ProtoConvError::FieldValueTooLong {
            field_name: msg_desc.name_str().to_string(),
            value_len: padded_body_len,
            max_len: 65535 * 4,
        })?;

    let header = TlvHeader {
        tag: u32::from_le_bytes(tag),
        word_len,
        reserved: 0,
        flags: TlvFlags::new().with_padding_bytes(padding_bytes),
    };

    // Cast the Vec<u32> to a mutable byte slice using zerocopy and write the header
    let out_bytes = out.as_mut_bytes();
    out_bytes[header_start_bytes..header_start_bytes + header_len]
        .copy_from_slice(header.as_bytes());

    Ok(())
}

/// Encodes only the raw body of a message (fixed struct and dynamic TLVs), without any TLV header.
/// Returns the exact end position in bytes of the unpadded body payload.
fn encode_message_body<'a>(
    desc_set: &'a FileDescriptorSet,
    msg_desc: descriptor_rust_proto::DescriptorProtoView<'a>,
    proto_bytes: &[u8],
    out: &mut Vec<u32>,
    body_start: usize,
) -> Result<usize, ProtoConvError> {
    // 1. Resolve and validate the entire message layout upfront
    let layout = msg_desc.tlv_layout(desc_set)?;

    // 2. Write placeholder for the message body (grow only if needed)
    let fixed_struct_end = body_start + layout.fixed_struct_size();
    let required_words = fixed_struct_end.div_ceil(4);
    if required_words > out.len() {
        out.resize(required_words, 0);
    }
    let mut exact_body_end = fixed_struct_end;

    // 3. Parse and encode the message based on its layout strategy!
    match layout {
        TlvLayout::Standard {
            fields,
            fixed_struct_size: _,
        } => {
            let mut reader = ProtoReader::new(proto_bytes);
            while !reader.is_eof() {
                let (field_number, record) = reader.read_record()?;

                let field_layout = match fields.get(&field_number) {
                    Some(l) => l,
                    None => continue,
                };

                let Some(field_desc) = msg_desc.find_field(field_number) else {
                    continue;
                };

                match field_layout {
                    FieldLayout::Fixed {
                        offset,
                        packed_type,
                    } => {
                        let size = packed_type.size();
                        let val_pos = body_start + offset;
                        let required_words = (val_pos + size).div_ceil(4);
                        if required_words <= out.len() {
                            if let Record::LengthDelimited(src_bytes) = record {
                                // If the field is a nested message, recursively encode its body inline!
                                if field_desc.r#type() == Type::Message
                                    || field_desc.r#type() == Type::Group
                                {
                                    let type_name_raw = field_desc
                                        .type_name()
                                        .to_str()
                                        .map_err(|_| ProtoConvError::InvalidUtf8)?;
                                    let type_name =
                                        type_name_raw.strip_prefix('.').unwrap_or(type_name_raw);

                                    let child_desc = find_message_descriptor(desc_set, type_name)
                                        .ok_or_else(|| {
                                        ProtoConvError::MessageNotFound(type_name.to_string())
                                    })?;

                                    // Recursively encode child body directly in place inside parent's buffer!
                                    encode_message_body(
                                        desc_set, child_desc, src_bytes, out, val_pos,
                                    )?;
                                } else {
                                    // Standard inline string or bytes
                                    if field_desc.r#type() == Type::Bytes {
                                        if src_bytes.len() != size {
                                            return Err(ProtoConvError::ByteFieldLengthMismatch {
                                                field_name: field_desc.name_str().to_string(),
                                                actual_len: src_bytes.len(),
                                                expected_len: size,
                                            });
                                        }
                                    } else if src_bytes.len() > size {
                                        return Err(ProtoConvError::FieldValueTooLong {
                                            field_name: field_desc.name_str().to_string(),
                                            value_len: src_bytes.len(),
                                            max_len: size,
                                        });
                                    }
                                    let copy_len = src_bytes.len();

                                    // Cast the Vec<u32> to mutable byte slice and copy
                                    let out_bytes = out.as_mut_bytes();
                                    out_bytes[val_pos..val_pos + copy_len]
                                        .copy_from_slice(&src_bytes[..copy_len]);
                                    if copy_len < size {
                                        out_bytes[val_pos + copy_len..val_pos + size].fill(0);
                                    }
                                }
                            } else {
                                let val = record
                                    .decode_u64(FieldType(i32::from(field_desc.r#type())))
                                    .map_err(|_| {
                                        ProtoConvError::UnsupportedWireType(record.wire_type_u8())
                                    })?;

                                let field_name = field_desc.name_str();
                                if !packed_type.is_float() {
                                    validate_value_range(
                                        val,
                                        packed_type.is_signed(),
                                        size * 8,
                                        field_name,
                                    )?;
                                }

                                let out_bytes = out.as_mut_bytes();
                                match size {
                                    1 => out_bytes[val_pos] = val as u8,
                                    2 => out_bytes[val_pos..val_pos + 2]
                                        .copy_from_slice(&(val as u16).to_le_bytes()),
                                    4 => out_bytes[val_pos..val_pos + 4]
                                        .copy_from_slice(&(val as u32).to_le_bytes()),
                                    8 => out_bytes[val_pos..val_pos + 8]
                                        .copy_from_slice(&val.to_le_bytes()),
                                    _ => return Err(ProtoConvError::VarintDecodeError),
                                }
                            }
                        }
                    }
                    FieldLayout::Tlv { .. } => {
                        let child_bytes = match record {
                            Record::LengthDelimited(bytes) => bytes,
                            _ => {
                                return Err(ProtoConvError::UnsupportedWireType(
                                    record.wire_type_u8(),
                                ));
                            }
                        };

                        let type_name_raw = field_desc
                            .type_name()
                            .to_str()
                            .map_err(|_| ProtoConvError::InvalidUtf8)?;
                        let type_name = type_name_raw.strip_prefix('.').unwrap_or(type_name_raw);

                        let child_desc =
                            find_message_descriptor(desc_set, type_name).ok_or_else(|| {
                                ProtoConvError::MessageNotFound(type_name.to_string())
                            })?;

                        // Recursive call to encode_message (since it's a dynamic sub-TLV, it must have a header!)
                        encode_message(desc_set, child_desc, child_bytes, out)?;
                        exact_body_end = out.len() * 4;
                    }
                    FieldLayout::ExtraData => {
                        let child_bytes = match record {
                            Record::LengthDelimited(bytes) => bytes,
                            _ => {
                                return Err(ProtoConvError::UnsupportedWireType(
                                    record.wire_type_u8(),
                                ));
                            }
                        };
                        let start_pos = fixed_struct_end;
                        let src_len = child_bytes.len();
                        let target_end = start_pos
                            .checked_add(src_len)
                            .ok_or(ProtoConvError::VarintDecodeError)?;
                        let target_words = target_end.div_ceil(4);
                        out.truncate(target_words);
                        if target_words > out.len() {
                            out.resize(target_words, 0);
                        }
                        let out_bytes = out.as_mut_bytes();
                        out_bytes[start_pos..start_pos + src_len].copy_from_slice(child_bytes);
                        if target_end < target_words * 4 {
                            out_bytes[target_end..target_words * 4].fill(0);
                        }
                        exact_body_end = target_end;
                    }
                }
            }
        }
        TlvLayout::BitPacked { fields, backing } => {
            // --- 2. Bit-Packed Message Serialization ---
            let total_size = backing.size();
            let mut accum = 0u64;

            // Gather, validate, and pack all field values in a single pass over the protobuf stream!
            let mut reader = ProtoReader::new(proto_bytes);
            while !reader.is_eof() {
                let (field_number, record) = reader.read_record()?;
                let Some(bit_field) = fields.get(&field_number) else {
                    continue;
                };
                let Some(fd) = msg_desc.find_field(field_number) else {
                    continue;
                };
                let val = record
                    .decode_u64(FieldType(i32::from(fd.r#type())))
                    .map_err(|_| ProtoConvError::UnsupportedWireType(record.wire_type_u8()))?;

                let field_name = fd.name_str();
                let is_signed = fd
                    .r#type()
                    .primitive_info()
                    .is_some_and(|info| info.is_signed);
                validate_value_range(val, is_signed, bit_field.bit_len, field_name)?;

                // Clear any previously written bits for this field to ensure standard overriding behavior
                let mask = mask_for_bits(bit_field.bit_len);
                accum &= !(mask << bit_field.bit_offset);
                accum |= (val & mask) << bit_field.bit_offset;
            }

            // Write the accumulated bytes directly into the output buffer
            let backing_bytes = accum.to_le_bytes();
            let out_bytes = out.as_mut_bytes();
            out_bytes[body_start..body_start + total_size]
                .copy_from_slice(&backing_bytes[..total_size]);
            exact_body_end = body_start + total_size;
        }
    }
    Ok(exact_body_end)
}

fn mask_for_bits(bit_len: usize) -> u64 {
    if bit_len >= 64 {
        u64::MAX
    } else {
        (1u64 << bit_len) - 1
    }
}

/// Sign-extends a `val` of width `bit_len` to a 64-bit signed integer represented as `u64`.
///
/// `bit_len` must be between 1 and 64 inclusive.
fn sign_extend(val: u64, bit_len: usize) -> u64 {
    if bit_len == 0 || bit_len >= 64 {
        val
    } else {
        let shift = 64 - bit_len;
        ((val << shift) as i64 >> shift) as u64
    }
}

fn validate_value_range(
    val: u64,
    is_signed: bool,
    bit_len: usize,
    field_name: &str,
) -> Result<(), ProtoConvError> {
    let fits = if bit_len >= 64 {
        true
    } else if is_signed {
        sign_extend(val, bit_len) == val
    } else {
        (val >> bit_len) == 0
    };

    if !fits {
        return Err(ProtoConvError::FieldValueOutOfRange {
            field_name: field_name.to_string(),
            value: val,
            bit_len,
            is_signed,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use openprot_tlv::TlvData;
    use protobuf::Serialize;

    use edge_cases_rust_proto::__unstable::SHARED_TLV_TEST_EDGE_CASES_DESCRIPTOR_INFO;
    use soc_rust_proto::__unstable::SHARED_TLV_TEST_SOC_DESCRIPTOR_INFO;

    #[test]
    fn test_sign_extend() {
        // 8-bit sign extension
        assert_eq!(sign_extend(0x7F, 8), 0x7F); // 127
        assert_eq!(sign_extend(0x80, 8), 0xFFFFFFFFFFFFFF80); // -128
        assert_eq!(sign_extend(0xFF, 8), 0xFFFFFFFFFFFFFFFF); // -1

        // 16-bit sign extension
        assert_eq!(sign_extend(0x7FFF, 16), 0x7FFF); // 32767
        assert_eq!(sign_extend(0x8000, 16), 0xFFFFFFFFFFFF8000); // -32768

        // 32-bit sign extension
        assert_eq!(sign_extend(0x7FFFFFFF, 32), 0x7FFFFFFF);
        assert_eq!(sign_extend(0x80000000, 32), 0xFFFFFFFF80000000);
        assert_eq!(sign_extend(0xFFFFFFFB, 32), 0xFFFFFFFFFFFFFFFB); // -5

        // Arbitrary width (e.g. 11-bit)
        assert_eq!(sign_extend(0x3FF, 11), 0x3FF); // 1023
        assert_eq!(sign_extend(0x400, 11), 0xFFFFFFFFFFFFFC00); // -1024
        assert_eq!(sign_extend(0x79C, 11), 0xFFFFFFFFFFFFFF9C); // -100

        // 64-bit (no-op)
        assert_eq!(sign_extend(0xFFFFFFFFFFFFFFFB, 64), 0xFFFFFFFFFFFFFFFB);
    }

    #[test]
    fn test_proto_to_tlv_system_hierarchy() {
        // 1. Build the nested topology containing all three accelerators using the proto! macro
        let system = protobuf::proto!(soc_rust_proto::System {
            vendor_id: 32898,
            product_id: 4660,
            total_mem_mib: 65536,
            system_name: "MyAwesomeSystem".to_string(),
            system_uuid: vec![
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
                0x0F, 0x10,
            ],
            cores: [soc_rust_proto::CpuCore {
                base_frequency_mhz: 3600,
                id: soc_rust_proto::CoreIdentifier {
                    model_id: 137,
                    revision: 3,
                },
                cache: soc_rust_proto::CacheInfo {
                    level: 1,
                    size_kib: 64,
                    associativity: 8,
                },
                execution_units: [
                    soc_rust_proto::ExecutionUnit {
                        unit_type: 0,
                        pipeline_stages: 5,
                        state: soc_rust_proto::ExecutionUnitState::EuStateLarge,
                        power_mw: 350,
                    },
                    soc_rust_proto::ExecutionUnit {
                        unit_type: 1,
                        pipeline_stages: 8,
                        state: soc_rust_proto::ExecutionUnitState::EuStateIdle,
                        power_mw: 50,
                    },
                ],
            }],
            bus: soc_rust_proto::SystemBus {
                bus_type: 1,
                width_bits: 64,
                speed_mhz: 3200,
                features: soc_rust_proto::BusFeatures {
                    is_primary: true,
                    supports_dma: false,
                    supports_coherent: true,
                    burst_len_log2: 4,
                },
            },
            accelerators: [
                protobuf::proto!(soc_rust_proto::Accelerator {
                    gpu: soc_rust_proto::GpuAccelerator {
                        cores: 512,
                        frequency_mhz: 1200,
                    }
                }),
                protobuf::proto!(soc_rust_proto::Accelerator {
                    npu: soc_rust_proto::NpuAccelerator { tops: 42 }
                }),
                protobuf::proto!(soc_rust_proto::Accelerator {
                    crypto: soc_rust_proto::CryptoAccelerator {
                        key_size_bits: 256,
                        supported_ciphers: b"AES,RSA".to_vec(),
                    }
                }),
            ],
        });

        // 2. Convert to TLV using our library's message_to_tlv function!
        let tlv_words = message_to_tlv(&SHARED_TLV_TEST_SOC_DESCRIPTOR_INFO, &system)
            .expect("Failed to convert proto to TLV!");

        // 3. Verify the exact expected byte representation
        let mut expected = Vec::new();

        // --- System Header ---
        expected.extend_from_slice(b"SYS_"); // tag
        expected.extend_from_slice(&[0x35, 0x00, 0x00, 0x00]); // word_len: 53, reserved: 0, flags: 0

        // --- System Fixed Struct (44 bytes) ---
        expected.extend_from_slice(&32898u32.to_le_bytes()); // vendor_id (offset 0)
        expected.extend_from_slice(&4660u32.to_le_bytes()); // product_id (offset 4)
        expected.extend_from_slice(&65536u32.to_le_bytes()); // total_mem_mib (offset 8)

        // system_name (offset 12, 16 bytes: "MyAwesomeSystem" + 1 null padding byte)
        expected.extend_from_slice(b"MyAwesomeSystem\0");

        // system_uuid (offset 28, 16 bytes)
        expected.extend_from_slice(&[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ]);

        // --- CpuCore Sub-TLV (72 bytes) ---
        expected.extend_from_slice(b"CORE"); // tag
        expected.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // word_len: 16, reserved: 0, flags: 0
        expected.extend_from_slice(&3600u32.to_le_bytes()); // base_frequency_mhz (offset 0)
        expected.extend_from_slice(&137u32.to_le_bytes()); // id.model_id (offset 4)
        expected.extend_from_slice(&3u32.to_le_bytes()); // id.revision (offset 8)

        // CpuCore -> CacheInfo Sub-TLV (20 bytes)
        expected.extend_from_slice(b"CACH"); // tag
        expected.extend_from_slice(&[0x03, 0x00, 0x00, 0x00]); // word_len: 3, reserved: 0, flags: 0
        expected.extend_from_slice(&1u32.to_le_bytes()); // level
        expected.extend_from_slice(&64u32.to_le_bytes()); // size_kib
        expected.extend_from_slice(&8u32.to_le_bytes()); // associativity

        // CpuCore -> First ExecutionUnit Sub-TLV (16 bytes)
        expected.extend_from_slice(b"EXEU"); // tag
        expected.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]); // word_len: 2, reserved: 0, flags: 0
        expected.push(0); // unit_type (offset 0, 1 byte)
        expected.push(5); // pipeline_stages (offset 1, 1 byte)
        expected.push(150); // state (offset 2, 1 byte)
        expected.push(0); // padding (offset 3, 1 byte)
        expected.extend_from_slice(&350u16.to_le_bytes()); // power_mw (offset 4, 2 bytes) -> [94, 1]
        expected.extend_from_slice(&[0u8; 2]); // body padding to 4 bytes

        // CpuCore -> Second ExecutionUnit Sub-TLV (16 bytes)
        expected.extend_from_slice(b"EXEU"); // tag
        expected.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]); // word_len: 2, reserved: 0, flags: 0
        expected.push(1); // unit_type (offset 0, 1 byte)
        expected.push(8); // pipeline_stages (offset 1, 1 byte)
        expected.push(0); // state (offset 2, 1 byte)
        expected.push(0); // padding (offset 3, 1 byte)
        expected.extend_from_slice(&50u16.to_le_bytes()); // power_mw (offset 4, 2 bytes) -> [50, 0]
        expected.extend_from_slice(&[0u8; 2]); // body padding to 4 bytes

        // --- SystemBus Sub-TLV (24 bytes) ---
        expected.extend_from_slice(b"SBUS"); // tag
        expected.extend_from_slice(&[0x04, 0x00, 0x00, 0x00]); // word_len: 4, reserved: 0, flags: 0
        expected.extend_from_slice(&1u32.to_le_bytes()); // bus_type
        expected.extend_from_slice(&64u32.to_le_bytes()); // width_bits
        expected.extend_from_slice(&3200u32.to_le_bytes()); // speed_mhz
        expected.push(37); // features (offset 12, 1 byte)
        expected.extend_from_slice(&[0u8; 3]); // body padding to 4 bytes

        // --- First Accelerator Sub-TLV: GPU (24 bytes) ---
        expected.extend_from_slice(b"ACCL"); // tag
        expected.extend_from_slice(&[0x04, 0x00, 0x00, 0x00]); // word_len: 4, reserved: 0, flags: 0
        expected.extend_from_slice(b"GPU_"); // tag
        expected.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]); // word_len: 2, reserved: 0, flags: 0
        expected.extend_from_slice(&512u32.to_le_bytes()); // cores
        expected.extend_from_slice(&1200u32.to_le_bytes()); // frequency_mhz

        // --- Second Accelerator Sub-TLV: NPU (20 bytes) ---
        expected.extend_from_slice(b"ACCL"); // tag
        expected.extend_from_slice(&[0x03, 0x00, 0x00, 0x00]); // word_len: 3, reserved: 0, flags: 0
        expected.extend_from_slice(b"NPU_"); // tag
        expected.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // word_len: 1, reserved: 0, flags: 0
        expected.extend_from_slice(&42u32.to_le_bytes()); // tops

        // --- Third Accelerator Sub-TLV: Crypto (28 bytes) ---
        expected.extend_from_slice(b"ACCL"); // tag
        expected.extend_from_slice(&[0x05, 0x00, 0x00, 0x00]); // word_len: 5, reserved: 0, flags: 0
        expected.extend_from_slice(b"CRYP"); // tag
        expected.extend_from_slice(&[0x03, 0x00, 0x00, 0x01]); // word_len: 3, reserved: 0, flags: 1
        expected.extend_from_slice(&256u32.to_le_bytes()); // key_size_bits
        expected.extend_from_slice(b"AES,RSA\0"); // supported_ciphers

        assert_eq!(tlv_words.as_bytes(), expected);

        // 4. Verify the output by parsing it using the generated zero-copy Rust structures!
        use openprot_tlv::TlvObject;
        use soc_tlv::*;

        let tlv_data = openprot_tlv::TlvData::overlay(&tlv_words);

        // Verify there is exactly one top-level TLV and it is System
        let mut top_any_iter = tlv_data.iter::<openprot_tlv::TlvAny>();
        let top_item = top_any_iter.next().unwrap();
        assert_eq!(top_item.container.header.tag, System::TAG);
        assert!(
            top_any_iter.next().is_none(),
            "Expected no other top-level TLVs"
        );

        // Assert System fields
        let system_tlv = tlv_data.iter::<System>().next().unwrap();
        assert_eq!(system_tlv.data.vendor_id, 32898);
        assert_eq!(system_tlv.data.product_id, 4660);
        assert_eq!(system_tlv.data.total_mem_mib, 65536);
        assert_eq!(&system_tlv.data.system_name[..15], b"MyAwesomeSystem");
        assert_eq!(system_tlv.data.system_name[15], 0);
        assert_eq!(
            system_tlv.data.system_uuid,
            [0x04030201, 0x08070605, 0x0C0B0A09, 0x100F0E0D]
        );

        // Assert Nested CpuCore via generated getter, and ensure iterator is exhausted
        let mut cores_iter = system_tlv.cores();
        let core = cores_iter.next().unwrap();
        assert_eq!(core.data.base_frequency_mhz, 3600);
        assert_eq!(core.data.id.model_id, 137);
        assert_eq!(core.data.id.revision, 3);
        assert!(cores_iter.next().is_none(), "Expected exactly one CpuCore");

        // Assert Nested CacheInfo inside CpuCore via generated getter
        let cache = core.cache().unwrap();
        assert_eq!(cache.data.level, 1);
        assert_eq!(cache.data.size_kib, 64);
        assert_eq!(cache.data.associativity, 8);

        // Assert Nested ExecutionUnits inside CpuCore via generated getter, and ensure iterator is exhausted
        let mut eu_iter = core.execution_units();

        let eu1 = eu_iter.next().unwrap();
        assert_eq!(eu1.data.unit_type, 0);
        assert_eq!(eu1.data.pipeline_stages, 5);
        assert_eq!(eu1.data.state, ExecutionUnitState::LARGE); // EuStateLarge
        assert_eq!(eu1.data.power_mw, 350);

        let eu2 = eu_iter.next().unwrap();
        assert_eq!(eu2.data.unit_type, 1);
        assert_eq!(eu2.data.pipeline_stages, 8);
        assert_eq!(eu2.data.state, ExecutionUnitState::IDLE); // EuStateIdle
        assert_eq!(eu2.data.power_mw, 50);

        assert!(
            eu_iter.next().is_none(),
            "Expected exactly two ExecutionUnits"
        );

        // Assert Nested SystemBus via generated getter
        let bus = system_tlv.bus().unwrap();
        assert_eq!(bus.data.bus_type, 1);
        assert_eq!(bus.data.width_bits, 64);
        assert_eq!(bus.data.speed_mhz, 3200);
        assert!(bus.data.features.is_primary());
        assert!(!bus.data.features.supports_dma());
        assert!(bus.data.features.supports_coherent());
        assert_eq!(bus.data.features.burst_len_log2(), 4);

        // Assert Nested Accelerators via generated getter, and ensure iterator is exhausted
        let mut accel_iter = system_tlv.accelerators();

        // 1. GPU
        let accel_gpu = accel_iter.next().unwrap();
        match accel_gpu.config().unwrap() {
            AcceleratorConfig::Gpu(gpu_item) => {
                assert_eq!(gpu_item.data.cores, 512);
                assert_eq!(gpu_item.data.frequency_mhz, 1200);
            }
            _ => panic!("Expected GPU variant"),
        }
        assert!(accel_gpu.npu().is_none());
        assert!(accel_gpu.crypto().is_none());

        // 2. NPU
        let accel_npu = accel_iter.next().unwrap();
        match accel_npu.config().unwrap() {
            AcceleratorConfig::Npu(npu_item) => {
                assert_eq!(npu_item.data.tops, 42);
            }
            _ => panic!("Expected NPU variant"),
        }
        assert!(accel_npu.gpu().is_none());
        assert!(accel_npu.crypto().is_none());

        // 3. Crypto
        let accel_crypto = accel_iter.next().unwrap();
        match accel_crypto.config().unwrap() {
            AcceleratorConfig::Crypto(crypto_item) => {
                assert_eq!(crypto_item.data.key_size_bits, 256);
                assert_eq!(crypto_item.supported_ciphers(), b"AES,RSA");
            }
            _ => panic!("Expected Crypto variant"),
        }
        assert!(accel_crypto.gpu().is_none());
        assert!(accel_crypto.npu().is_none());

        assert!(
            accel_iter.next().is_none(),
            "Expected exactly three accelerators"
        );
    }

    #[test]
    fn test_proto_to_tlv_recursive_tree() {
        use edge_cases_tlv::NodeExt;

        // Construct a deep recursive binary tree:
        //        10
        //       /  \
        //      5   15
        //     /
        //    2
        let tree = protobuf::proto!(edge_cases_rust_proto::Node {
            value: 10,
            children: [
                edge_cases_rust_proto::Node {
                    value: 5,
                    children: [edge_cases_rust_proto::Node { value: 2 },],
                },
                edge_cases_rust_proto::Node { value: 15 },
            ],
        });

        // Convert to TLV using the edge cases descriptor info
        let tlv_words = message_to_tlv(&SHARED_TLV_TEST_EDGE_CASES_DESCRIPTOR_INFO, &tree)
            .expect("Failed to convert Node tree to TLV!");

        // Overlay the container zero-copy
        let tlv_data = TlvData::overlay(&tlv_words);

        let mut root_iter = tlv_data.iter::<edge_cases_tlv::Node>();
        let node_10 = root_iter.next().expect("Failed to get root node");
        assert_eq!(node_10.data.value, 10);

        let mut children_10 = node_10.children();

        // Verify left child (node 5)
        let node_5 = children_10.next().unwrap();
        assert_eq!(node_5.data.value, 5);

        let mut children_5 = node_5.children();

        // Verify left-left grandchild (node 2)
        let node_2 = children_5.next().unwrap();
        assert_eq!(node_2.data.value, 2);
        assert!(node_2.children().next().is_none());

        assert!(children_5.next().is_none());

        // Verify right child (node 15)
        let node_15 = children_10.next().unwrap();
        assert_eq!(node_15.data.value, 15);
        assert!(node_15.children().next().is_none());

        assert!(children_10.next().is_none());
    }

    #[test]
    fn test_proto_to_tlv_string_too_long() {
        let system = protobuf::proto!(soc_rust_proto::System {
            vendor_id: 32898,
            product_id: 4660,
            total_mem_mib: 65536,
            system_name: "ThisSystemNameIsWayTooLongFor16Bytes".to_string(), // 36 bytes!
            system_uuid: vec![0xAA, 0xBB, 0xCC, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        });

        let err = message_to_tlv(&SHARED_TLV_TEST_SOC_DESCRIPTOR_INFO, &system).unwrap_err();

        assert_eq!(
            err.to_string(),
            "Value for field 'system_name' is too long (length is 36 bytes, but target packed size in the fixed struct is only 16 bytes)."
        );
    }

    #[test]
    fn test_proto_to_tlv_string_utf8_fixed() {
        use soc_tlv::System;

        let system = protobuf::proto!(soc_rust_proto::System {
            vendor_id: 32898,
            product_id: 4660,
            total_mem_mib: 65536,
            system_name: "MySystém".to_string(), // UTF-8 string (9 bytes in UTF-8)
            system_uuid: vec![0xAA, 0xBB, 0xCC, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        });

        let tlv_words = message_to_tlv(&SHARED_TLV_TEST_SOC_DESCRIPTOR_INFO, &system)
            .expect("Should cleanly convert inline UTF-8 string without error!");

        let tlv_data = openprot_tlv::TlvData::overlay(&tlv_words);
        let system_tlv = tlv_data.iter::<System>().next().unwrap();

        let mut expected_name = [0u8; 16];
        expected_name[..9].copy_from_slice("MySystém".as_bytes());
        assert_eq!(system_tlv.data.system_name, expected_name);
    }

    #[test]
    fn test_proto_to_tlv_string_extension_bstr_utf8() {
        use bstr::ByteSlice;
        use edge_cases_rust_proto::__unstable::SHARED_TLV_TEST_EDGE_CASES_DESCRIPTOR_INFO;
        use edge_cases_tlv::StringExtensionTestExt;

        let msg = protobuf::proto!(edge_cases_rust_proto::StringExtensionTest {
            text: "hello bstr 🌍".to_string(), // valid UTF-8 string including emoji
        });

        let tlv_words = message_to_tlv(&SHARED_TLV_TEST_EDGE_CASES_DESCRIPTOR_INFO, &msg)
            .expect("Failed to convert StringExtensionTest with UTF-8 to TLV!");

        let tlv_data = openprot_tlv::TlvData::overlay(&tlv_words);
        let item = tlv_data
            .iter::<edge_cases_tlv::StringExtensionTest>()
            .next()
            .expect("Should decode StringExtensionTest item");

        // 1. Assert direct comparison with string literal (zero-cost, works directly with UTF-8!)
        assert_eq!(item.text(), "hello bstr 🌍");

        // 2. A willing user can opt-in to validation or conversions using bstr methods
        assert_eq!(item.text().to_str().expect("Valid UTF-8"), "hello bstr 🌍");
    }

    #[test]
    fn test_proto_to_tlv_bytes_length_mismatch() {
        let system = protobuf::proto!(soc_rust_proto::System {
            vendor_id: 32898,
            product_id: 4660,
            total_mem_mib: 65536,
            system_name: "MyAwesomeSystem".to_string(),
            system_uuid: vec![0xAA, 0xBB, 0xCC], // Only 3 bytes, must be exactly 16!
        });

        let err = message_to_tlv(&SHARED_TLV_TEST_SOC_DESCRIPTOR_INFO, &system).unwrap_err();

        assert_eq!(
            err.to_string(),
            "Length of bytes field 'system_uuid' must match the target size exactly (expected 16 bytes, got 3 bytes)."
        );
    }

    #[test]
    fn test_proto_to_tlv_bit_fields() {
        let container = protobuf::proto!(edge_cases_rust_proto::RegisterContainer {
            reg: edge_cases_rust_proto::PackedRegister {
                enabled: true, // bit 0 = true (1)
                mode: 5,       // bits 1-3 = 5 (0b101)
                status: 9,     // bits 4-7 = 9 (0b1001)
                val: 123456,   // bits 8-31 = 123456 (0x01E240)
            },
            reg16: edge_cases_rust_proto::Packed16Register {
                flag: true, // bit 0 = true (1)
                mode: 6,    // bits 1-4 = 6 (0b0110) -> << 1 = 12
                val: 1000,  // bits 5-15 = 1000 -> << 5 = 32000
            },
            reg8: edge_cases_rust_proto::Packed8Register {
                flag: true, // bit 0 = true (1)
                status: 45, // bits 1-7 = 45 (0b0101101) -> << 1 = 90
            },
        });

        let tlv_words = message_to_tlv(&SHARED_TLV_TEST_EDGE_CASES_DESCRIPTOR_INFO, &container)
            .expect("Failed to convert RegisterContainer to TLV!");

        let mut expected = Vec::new();
        expected.extend_from_slice(b"CONT"); // tag
        expected.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]); // word_len: 2, reserved: 0, flags: 0

        // Combined 32-bit backing word of PackedRegister packed inline at offset 0:
        // val (123456 = 0x01E240) << 8 = 0x01E24000
        // status (9 = 0x9) << 4        = 0x00000090
        // mode (5 = 0x5) << 1          = 0x0000000A
        // enabled (true = 1)           = 0x00000001
        // Total                        = 0x01E2409B
        expected.extend_from_slice(&0x01E2409Bu32.to_le_bytes());

        // 16-bit backing word of Packed16Register packed inline at offset 4:
        // val (1000) << 5 = 32000
        // mode (6) << 1   = 12
        // flag (1)        = 1
        // Total u16       = 32013 (0x7D0D)
        expected.extend_from_slice(&32013u16.to_le_bytes());

        // 8-bit backing byte of Packed8Register packed inline at offset 6:
        // status (45) << 1 = 90
        // flag (1)        = 1
        // Total u8        = 91 (0x5B)
        expected.push(91u8);

        // Padding byte to align 8-byte container struct length (offset 7)
        expected.push(0u8);

        assert_eq!(tlv_words.as_bytes(), expected);
    }

    #[test]
    fn test_proto_to_tlv_sfixed_negative() {
        let msg = protobuf::proto!(edge_cases_rust_proto::SfixedTest {
            sfix: -5,
            sfix_i16: -100,
            sfix_i8: -12,
        });

        let tlv_words = message_to_tlv(&SHARED_TLV_TEST_EDGE_CASES_DESCRIPTOR_INFO, &msg)
            .expect("Failed to convert SfixedTest to TLV!");

        let mut expected = Vec::new();
        expected.extend_from_slice(b"SFIX"); // tag
        expected.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]); // word_len: 2, reserved: 0, flags: 0
        expected.extend_from_slice(&(-5i32).to_le_bytes()); // sfix (4 bytes)
        expected.extend_from_slice(&(-100i16).to_le_bytes()); // sfix_i16 (2 bytes)
        expected.push(-12i8 as u8); // sfix_i8 (1 byte)
        expected.push(0); // body padding to 8 bytes

        assert_eq!(tlv_words.as_bytes(), expected);
    }

    #[test]
    fn test_proto_to_tlv_extra_data() {
        use edge_cases_rust_proto::__unstable::SHARED_TLV_TEST_EDGE_CASES_DESCRIPTOR_INFO;
        use edge_cases_tlv::RawBytesExtensionTestExt;

        let version_msg = protobuf::proto!(edge_cases_rust_proto::RawBytesExtensionTest {
            payload: b"1.2.3".to_vec(),
        });

        let tlv_words = message_to_tlv(&SHARED_TLV_TEST_EDGE_CASES_DESCRIPTOR_INFO, &version_msg)
            .expect("Failed to convert RawBytesExtensionTest to TLV!");

        // Expected header:
        // Tag: 'RBXT'
        // word_len: 2 words (8 bytes)
        // flags: padding_bytes = 3 (8 - 5 = 3)
        let mut expected = Vec::new();
        expected.extend_from_slice(b"RBXT");
        expected.extend_from_slice(&[0x02, 0x00, 0x00, 0x03]);
        expected.extend_from_slice(b"1.2.3\0\0\0");

        assert_eq!(tlv_words.as_bytes(), expected);

        // Verify overlay & accessor round-trip decoding
        let tlv_data = openprot_tlv::TlvData::overlay(&tlv_words);
        let item = tlv_data
            .iter::<edge_cases_tlv::RawBytesExtensionTest>()
            .next()
            .expect("Should decode RawBytesExtensionTest item");

        assert_eq!(item.payload(), b"1.2.3");
    }

    #[test]
    fn test_proto_to_tlv_extra_data_nonzero_offset() {
        use soc_rust_proto::__unstable::SHARED_TLV_TEST_SOC_DESCRIPTOR_INFO;
        use soc_tlv::CryptoAcceleratorExt;

        let msg = protobuf::proto!(soc_rust_proto::CryptoAccelerator {
            key_size_bits: 512,
            supported_ciphers: b"CHACHA20-POLY1305".to_vec(),
        });

        let tlv_words = message_to_tlv(&SHARED_TLV_TEST_SOC_DESCRIPTOR_INFO, &msg)
            .expect("Failed to convert CryptoAccelerator to TLV!");

        // Expected header:
        // Tag: 'CRYP'
        // Fixed field key_size_bits: 4 bytes (offset 0..4).
        // supported_ciphers: 17 bytes (offset 4..21).
        // Total unpadded payload: 21 bytes. Padded: 24 bytes (6 words). Padding bytes: 3.
        let mut expected = Vec::new();
        expected.extend_from_slice(b"CRYP");
        expected.extend_from_slice(&[0x06, 0x00, 0x00, 0x03]); // word_len: 6, reserved: 0, flags: 3
        expected.extend_from_slice(&512u32.to_le_bytes());
        expected.extend_from_slice(b"CHACHA20-POLY1305\0\0\0");

        assert_eq!(tlv_words.as_bytes(), expected);

        let tlv_data = openprot_tlv::TlvData::overlay(&tlv_words);
        let item = tlv_data
            .iter::<soc_tlv::CryptoAccelerator>()
            .next()
            .expect("Should decode CryptoAccelerator item");

        assert_eq!(item.data.key_size_bits, 512);
        assert_eq!(item.supported_ciphers(), b"CHACHA20-POLY1305");
    }

    #[test]
    fn test_proto_to_tlv_nested_unaligned_extra_data() {
        use edge_cases_rust_proto::__unstable::SHARED_TLV_TEST_EDGE_CASES_DESCRIPTOR_INFO;
        use edge_cases_tlv::*;

        let container_msg = protobuf::proto!(edge_cases_rust_proto::ExtensionContainer {
            id: 42,
            child_ext: protobuf::proto!(edge_cases_rust_proto::RawBytesExtensionTest {
                payload: b"1.2.3-unaligned_suffix".to_vec(), // 22 bytes (22 % 4 == 2)
            }),
            next_child: protobuf::proto!(edge_cases_rust_proto::RegisterContainer {
                reg: protobuf::proto!(edge_cases_rust_proto::PackedRegister {
                    enabled: true,
                    mode: 5,
                    status: 9,
                    val: 123456,
                }),
                reg16: protobuf::proto!(edge_cases_rust_proto::Packed16Register {
                    flag: true,
                    mode: 6,
                    val: 1000,
                }),
                reg8: protobuf::proto!(edge_cases_rust_proto::Packed8Register {
                    flag: true,
                    status: 45,
                }),
            }),
        });

        let tlv_words =
            message_to_tlv(&SHARED_TLV_TEST_EDGE_CASES_DESCRIPTOR_INFO, &container_msg)
                .expect("Failed to convert ExtensionContainer to TLV!");

        // Overlay TlvData and parse top-level container
        let tlv_data = openprot_tlv::TlvData::overlay(&tlv_words);
        let container_item = tlv_data
            .iter::<ExtensionContainer>()
            .next()
            .expect("Should decode ExtensionContainer");

        assert_eq!(container_item.data.id, 42);

        // Parse child RawBytesExtensionTest
        let child_ext_item = container_item
            .child_ext()
            .expect("Should decode RawBytesExtensionTest");

        // Assert unpadded raw bytes match exact 22 bytes
        assert_eq!(child_ext_item.payload(), b"1.2.3-unaligned_suffix");

        // Assert RegisterContainer sub-TLV following RawBytesExtensionTest is correctly word-aligned and decoded
        let next_child_item = container_item
            .next_child()
            .expect("Should decode RegisterContainer sub-TLV after RawBytesExtensionTest");

        // Explicitly assert pointer alignment of next_child_item's struct
        let next_child_ptr = (&next_child_item.data as *const _) as usize;
        assert_eq!(
            next_child_ptr % 4,
            0,
            "Next child pointer must be 4-byte aligned!"
        );

        assert_eq!(next_child_item.data.reg.val(), 123456);
        assert_eq!(next_child_item.data.reg16.val(), 1000);
        assert_eq!(next_child_item.data.reg8.status(), 45);
    }

    #[test]
    fn test_proto_to_tlv_extra_data_duplicate_field() {
        use edge_cases_rust_proto::__unstable::SHARED_TLV_TEST_EDGE_CASES_DESCRIPTOR_INFO;
        use edge_cases_tlv::RawBytesExtensionTestExt;
        use openprot_tlv_proto_meta::collect_descriptor_set;
        use openprot_tlv_proto_meta::find_message_descriptor;

        let desc_set =
            collect_descriptor_set(&SHARED_TLV_TEST_EDGE_CASES_DESCRIPTOR_INFO).unwrap();
        let msg_desc = find_message_descriptor(
            &desc_set,
            "openprot.tlv.test.edge_cases.RawBytesExtensionTest",
        )
        .unwrap();

        // Wire tag for field #1 with length-delimited wire type 2: (1 << 3) | 2 = 0x0A
        let mut duplicate_wire_bytes = Vec::new();
        // First occurrence: payload = "v1"
        duplicate_wire_bytes.extend_from_slice(&[0x0A, 0x02, b'v', b'1']);
        // Second occurrence (duplicate): payload = "v2"
        duplicate_wire_bytes.extend_from_slice(&[0x0A, 0x02, b'v', b'2']);

        let mut tlv_words = Vec::new();
        encode_message(&desc_set, msg_desc, &duplicate_wire_bytes, &mut tlv_words)
            .expect("Failed to encode duplicate wire bytes!");

        // Overlay TlvData and parse
        let tlv_data = openprot_tlv::TlvData::overlay(&tlv_words);
        let item = tlv_data
            .iter::<edge_cases_tlv::RawBytesExtensionTest>()
            .next()
            .expect("Should decode RawBytesExtensionTest item");

        // Protobuf spec rule: last occurrence wins.
        // Expected payload is b"v2" of length 2.
        assert_eq!(item.payload(), b"v2");
    }

    #[test]
    fn test_proto_to_tlv_unknown_fields() {
        let msg = protobuf::proto!(edge_cases_rust_proto::SfixedTest {
            sfix: -5,
            sfix_i16: -100,
            sfix_i8: -12,
        });

        let encoded_data = msg.serialize().expect("Failed to serialize SfixedTest");

        let mut proto_bytes = Vec::new();

        // Inject unknown varint field at the BEGINNING (field #777, varint wire type 0 => tag 6216)
        // 6216 in varint encoding: 6216 = (777 << 3) | 0 = 0x1848 -> [0xC8, 0x30]
        proto_bytes.extend_from_slice(&[0xC8, 0x30, 0x42]); // tag 6216, value 42

        // Inject unknown length-delimited field at the BEGINNING (field #666, wire type 2 => tag 5330)
        // 5330 in varint encoding: 5330 = (666 << 3) | 2 = 0x14D2 -> [0xD2, 0x2A]
        proto_bytes.extend_from_slice(&[0xD2, 0x2A, 0x06]); // tag 5330, len 6
        proto_bytes.extend_from_slice(b"header");

        // Insert the actual encoded data in the middle
        proto_bytes.extend_from_slice(&encoded_data);

        // Inject unknown varint field at the END (field #999, varint wire type 0 => tag 7992)
        // 7992 in varint encoding: 7992 = (999 << 3) | 0 = 0x1F38 -> [0xB8, 0x3E]
        proto_bytes.extend_from_slice(&[0xB8, 0x3E, 0x99, 0x01]); // tag 7992, value 153

        // Inject unknown length-delimited field at the END (field #888, wire type 2 => tag 7106)
        // 7106 in varint encoding: 7106 = (888 << 3) | 2 = 0x1BC2 -> [0xC2, 0x37]
        proto_bytes.extend_from_slice(&[0xC2, 0x37, 0x07]); // tag 7106, len 7
        proto_bytes.extend_from_slice(b"unknown");

        let tlv_words = proto_to_tlv_with_info(
            &SHARED_TLV_TEST_EDGE_CASES_DESCRIPTOR_INFO,
            std::any::type_name::<edge_cases_rust_proto::SfixedTest>(),
            &proto_bytes,
        )
        .expect("Failed to convert proto with unknown fields to TLV!");

        let mut expected = Vec::new();
        expected.extend_from_slice(b"SFIX"); // tag
        expected.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]); // word_len: 2, reserved: 0, flags: 0
        expected.extend_from_slice(&(-5i32).to_le_bytes()); // sfix (4 bytes)
        expected.extend_from_slice(&(-100i16).to_le_bytes()); // sfix_i16 (2 bytes)
        expected.push(-12i8 as u8); // sfix_i8 (1 byte)
        expected.push(0); // body padding to 8 bytes

        assert_eq!(tlv_words.as_bytes(), expected);
    }

    #[test]
    fn test_nested_message_collision() {
        let msg = protobuf::proto!(edge_cases_rust_proto::MessageCollisionContainer {
            local: edge_cases_rust_proto::message_collision_container::PackedRegister { val: 42 }
        });

        let tlv_words = message_to_tlv(&SHARED_TLV_TEST_EDGE_CASES_DESCRIPTOR_INFO, &msg)
            .expect("Failed to convert MessageCollisionContainer to TLV!");

        let mut expected = Vec::new();
        expected.extend_from_slice(b"COLL"); // tag
        expected.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // word_len: 1, reserved: 0, flags: 0
        expected.extend_from_slice(&42u32.to_le_bytes()); // val at offset 0

        assert_eq!(tlv_words.as_bytes(), expected);
    }

    #[test]
    fn test_direct_nested_message_serialization() {
        let msg = protobuf::proto!(
            edge_cases_rust_proto::message_collision_container::PackedRegister { val: 99 }
        );

        let tlv_words = message_to_tlv(&SHARED_TLV_TEST_EDGE_CASES_DESCRIPTOR_INFO, &msg)
            .expect("Failed to convert nested PackedRegister directly to TLV!");

        let mut expected = Vec::new();
        expected.extend_from_slice(b"NPK_"); // tag
        expected.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // word_len: 1, reserved: 0, flags: 0
        expected.extend_from_slice(&99u32.to_le_bytes()); // val at offset 0

        assert_eq!(tlv_words.as_bytes(), expected);
    }

    #[test]
    fn test_proto_to_tlv_floats() {
        let msg = protobuf::proto!(edge_cases_rust_proto::FloatTest {
            fval: -1.5,
            dval: -2.75,
        });

        let tlv_words = message_to_tlv(&SHARED_TLV_TEST_EDGE_CASES_DESCRIPTOR_INFO, &msg)
            .expect("Failed to convert FloatTest to TLV!");

        let mut expected = Vec::new();
        expected.extend_from_slice(b"FLOT"); // tag
        expected.extend_from_slice(&[0x04, 0x00, 0x00, 0x00]); // word_len: 4, reserved: 0, flags: 0
        expected.extend_from_slice(&(-1.5f32).to_bits().to_le_bytes()); // fval (4 bytes)
        expected.extend_from_slice(&[0u8; 4]); // padding
        expected.extend_from_slice(&(-2.75f64).to_bits().to_le_bytes()); // dval (8 bytes)

        assert_eq!(tlv_words.as_bytes(), expected);
    }

    #[test]
    fn test_proto_to_tlv_u64_alignment() {
        let msg = protobuf::proto!(edge_cases_rust_proto::U64AlignmentTest {
            val32: 0x12345678,
            val64: 0x0102030405060708,
        });

        let tlv_words = message_to_tlv(&SHARED_TLV_TEST_EDGE_CASES_DESCRIPTOR_INFO, &msg)
            .expect("Failed to convert U64AlignmentTest to TLV!");

        let mut expected = Vec::new();
        expected.extend_from_slice(b"ALGN"); // tag
        expected.extend_from_slice(&[0x03, 0x00, 0x00, 0x00]); // word_len: 3, reserved: 0, flags: 0
        expected.extend_from_slice(&0x12345678u32.to_le_bytes()); // val32 (4 bytes, offset 0)
        expected.extend_from_slice(&0x0102030405060708u64.to_le_bytes()); // val64 (8 bytes, offset 4)

        assert_eq!(tlv_words.as_bytes(), expected);
    }

    #[test]
    fn test_proto_to_tlv_sibling_inline_reuse() {
        let msg = protobuf::proto!(edge_cases_rust_proto::SiblingInlineParent {
            child1: edge_cases_rust_proto::SiblingInlineChild { val: 100 },
            child2: edge_cases_rust_proto::SiblingInlineChild { val: 200 },
        });

        let tlv_words = message_to_tlv(&SHARED_TLV_TEST_EDGE_CASES_DESCRIPTOR_INFO, &msg)
            .expect("Failed to convert SiblingInlineParent to TLV!");

        // Verify we can parse it back successfully
        let tlv_data = openprot_tlv::TlvData::overlay(&tlv_words);
        let mut iter = tlv_data.iter::<edge_cases_tlv::SiblingInlineParent>();
        let parent_item = iter.next().expect("Should have one SiblingInlineParent");
        assert!(iter.next().is_none());

        assert_eq!(
            parent_item.container.header.tag,
            u32::from_le_bytes(*b"SIBR")
        );
        assert_eq!(parent_item.data.child1.val, 100);
        assert_eq!(parent_item.data.child2.val, 200);
    }

    #[track_caller]
    fn run_all_types_test(
        msg: edge_cases_rust_proto::AllTypesTest,
        expected_struct: edge_cases_tlv::AllTypesTest,
    ) {
        let tlv_words = message_to_tlv(&SHARED_TLV_TEST_EDGE_CASES_DESCRIPTOR_INFO, &msg)
            .expect("Failed to convert AllTypesTest to TLV!");

        let tlv_data = openprot_tlv::TlvData::overlay(&tlv_words);
        let decoded = tlv_data
            .iter::<edge_cases_tlv::AllTypesTest>()
            .next()
            .unwrap();

        assert_eq!(*decoded.data, expected_struct);
    }

    #[track_caller]
    fn assert_overflow<F>(modify: F, expected_err: &str)
    where
        F: FnOnce(&mut edge_cases_rust_proto::AllTypesTest),
    {
        let mut msg = edge_cases_rust_proto::AllTypesTest::new();
        modify(&mut msg);
        let err = message_to_tlv(&SHARED_TLV_TEST_EDGE_CASES_DESCRIPTOR_INFO, &msg).unwrap_err();
        assert_eq!(err.to_string(), expected_err);
    }

    #[test]
    fn test_proto_to_tlv_all_types() {
        // Test case 1: Happy path with various typical custom-sized integer and float/double types
        run_all_types_test(
            protobuf::proto!(edge_cases_rust_proto::AllTypesTest {
                sint32_i8: -1,
                uint32_u8: 2,
                int32_i8: -3,
                int64_i8: -4,
                sfixed32_i8: -5,
                fixed32_u8: 6,
                sint64_i8: -7,
                uint64_u8: 8,
                bool_val: true,
                sint32_i16: -100,
                uint32_u16: 200,
                int32_i16: -300,
                int64_i16: -400,
                sfixed32_i16: -500,
                fixed32_u16: 600,
                sint64_i16: -700,
                uint64_u16: 800,
                sint32_i32: -10000,
                uint32_u32: 20000,
                int32_i32: -30000,
                sfixed32_i32: -40000,
                fixed32_u32: 50000,
                packed_reg: edge_cases_rust_proto::PackedSignedRegister {
                    sval: -5,
                    uval: 200,
                    flag: true,
                    sfix: -100,
                },
                float_val: 12.5,
                sint64_i32: -60000,
                uint64_u32: 70000,
                int64_i32: -80000,
                sint64_i64: -900000000,
                uint64_u64: 1000000000,
                int64_i64: -1100000000,
                double_val: -123.456,
            }),
            edge_cases_tlv::AllTypesTest {
                sint32_i8: -1,
                uint32_u8: 2,
                int32_i8: -3,
                int64_i8: -4,
                sfixed32_i8: -5,
                fixed32_u8: 6,
                sint64_i8: -7,
                uint64_u8: 8,
                bool_val: 1,
                sint32_i16: -100,
                uint32_u16: 200,
                int32_i16: -300,
                int64_i16: -400,
                sfixed32_i16: -500,
                fixed32_u16: 600,
                sint64_i16: -700,
                uint64_u16: 800,
                sint32_i32: -10000,
                uint32_u32: 20000,
                int32_i32: -30000,
                sfixed32_i32: -40000,
                fixed32_u32: 50000,
                packed_reg: edge_cases_tlv::PackedSignedRegister::new()
                    .with_sval(-5)
                    .with_uval(200)
                    .with_flag(true)
                    .with_sfix(-100),
                float_val: 12.5,
                sint64_i32: -60000,
                uint64_u32: 70000,
                int64_i32: -80000,
                sint64_i64: (-900000000i64).into(),
                uint64_u64: 1000000000u64.into(),
                int64_i64: (-1100000000i64).into(),
                double_val: (-123.456f64).into(),
                ..Default::default()
            },
        );

        // Test case 2: Minimum boundary values for all fields
        run_all_types_test(
            protobuf::proto!(edge_cases_rust_proto::AllTypesTest {
                sint32_i8: -128,
                uint32_u8: 0,
                int32_i8: -128,
                int64_i8: -128,
                sfixed32_i8: -128,
                fixed32_u8: 0,
                sint64_i8: -128,
                uint64_u8: 0,
                bool_val: false,
                sint32_i16: -32768,
                uint32_u16: 0,
                int32_i16: -32768,
                int64_i16: -32768,
                sfixed32_i16: -32768,
                fixed32_u16: 0,
                sint64_i16: -32768,
                uint64_u16: 0,
                sint32_i32: -2147483648,
                uint32_u32: 0,
                int32_i32: -2147483648,
                sfixed32_i32: -2147483648,
                fixed32_u32: 0,
                packed_reg: edge_cases_rust_proto::PackedSignedRegister {
                    sval: -128,
                    uval: 0,
                    flag: false,
                    sfix: -1024,
                },
                float_val: f32::MIN,
                sint64_i32: -2147483648,
                uint64_u32: 0,
                int64_i32: -2147483648,
                sint64_i64: i64::MIN,
                uint64_u64: 0,
                int64_i64: i64::MIN,
                double_val: f64::MIN,
            }),
            edge_cases_tlv::AllTypesTest {
                sint32_i8: -128,
                uint32_u8: 0,
                int32_i8: -128,
                int64_i8: -128,
                sfixed32_i8: -128,
                fixed32_u8: 0,
                sint64_i8: -128,
                uint64_u8: 0,
                bool_val: 0,
                sint32_i16: -32768,
                uint32_u16: 0,
                int32_i16: -32768,
                int64_i16: -32768,
                sfixed32_i16: -32768,
                fixed32_u16: 0,
                sint64_i16: -32768,
                uint64_u16: 0,
                sint32_i32: -2147483648,
                uint32_u32: 0,
                int32_i32: -2147483648,
                sfixed32_i32: -2147483648,
                fixed32_u32: 0,
                packed_reg: edge_cases_tlv::PackedSignedRegister::new()
                    .with_sval(-128)
                    .with_uval(0)
                    .with_flag(false)
                    .with_sfix(-1024),
                float_val: f32::MIN,
                sint64_i32: -2147483648,
                uint64_u32: 0,
                int64_i32: -2147483648,
                sint64_i64: i64::MIN.into(),
                uint64_u64: 0u64.into(),
                int64_i64: i64::MIN.into(),
                double_val: f64::MIN.into(),
                ..Default::default()
            },
        );

        // Test case 3: Maximum boundary values for all fields
        run_all_types_test(
            protobuf::proto!(edge_cases_rust_proto::AllTypesTest {
                sint32_i8: 127,
                uint32_u8: 255,
                int32_i8: 127,
                int64_i8: 127,
                sfixed32_i8: 127,
                fixed32_u8: 255,
                sint64_i8: 127,
                uint64_u8: 255,
                bool_val: true,
                sint32_i16: 32767,
                uint32_u16: 65535,
                int32_i16: 32767,
                int64_i16: 32767,
                sfixed32_i16: 32767,
                fixed32_u16: 65535,
                sint64_i16: 32767,
                uint64_u16: 65535,
                sint32_i32: 2147483647,
                uint32_u32: 4294967295,
                int32_i32: 2147483647,
                sfixed32_i32: 2147483647,
                fixed32_u32: 4294967295,
                packed_reg: edge_cases_rust_proto::PackedSignedRegister {
                    sval: 127,
                    uval: 255,
                    flag: true,
                    sfix: 1023,
                },
                float_val: f32::MAX,
                sint64_i32: 2147483647,
                uint64_u32: 4294967295,
                int64_i32: 2147483647,
                sint64_i64: i64::MAX,
                uint64_u64: u64::MAX,
                int64_i64: i64::MAX,
                double_val: f64::MAX,
            }),
            edge_cases_tlv::AllTypesTest {
                sint32_i8: 127,
                uint32_u8: 255,
                int32_i8: 127,
                int64_i8: 127,
                sfixed32_i8: 127,
                fixed32_u8: 255,
                sint64_i8: 127,
                uint64_u8: 255,
                bool_val: 1,
                sint32_i16: 32767,
                uint32_u16: 65535,
                int32_i16: 32767,
                int64_i16: 32767,
                sfixed32_i16: 32767,
                fixed32_u16: 65535,
                sint64_i16: 32767,
                uint64_u16: 65535,
                sint32_i32: 2147483647,
                uint32_u32: 4294967295,
                int32_i32: 2147483647,
                sfixed32_i32: 2147483647,
                fixed32_u32: 4294967295,
                packed_reg: edge_cases_tlv::PackedSignedRegister::new()
                    .with_sval(127)
                    .with_uval(255)
                    .with_flag(true)
                    .with_sfix(1023),
                float_val: f32::MAX,
                sint64_i32: 2147483647,
                uint64_u32: 4294967295,
                int64_i32: 2147483647,
                sint64_i64: i64::MAX.into(),
                uint64_u64: u64::MAX.into(),
                int64_i64: i64::MAX.into(),
                double_val: f64::MAX.into(),
                ..Default::default()
            },
        );

        // --- 8-bit Signed Fields (overflow, underflow, and protobuf limits) ---

        // sint32_i8 (protobuf i32, packed i8)
        assert_overflow(
            |m| m.set_sint32_i8(128),
            "Value 128 for field 'sint32_i8' is out of range for its packed bit-width of 8 bits (valid range is -128..=127).",
        );
        assert_overflow(
            |m| m.set_sint32_i8(-129),
            "Value -129 for field 'sint32_i8' is out of range for its packed bit-width of 8 bits (valid range is -128..=127).",
        );
        assert_overflow(
            |m| m.set_sint32_i8(i32::MAX),
            "Value 2147483647 for field 'sint32_i8' is out of range for its packed bit-width of 8 bits (valid range is -128..=127).",
        );
        assert_overflow(
            |m| m.set_sint32_i8(i32::MIN),
            "Value -2147483648 for field 'sint32_i8' is out of range for its packed bit-width of 8 bits (valid range is -128..=127).",
        );

        // int32_i8 (protobuf i32, packed i8)
        assert_overflow(
            |m| m.set_int32_i8(128),
            "Value 128 for field 'int32_i8' is out of range for its packed bit-width of 8 bits (valid range is -128..=127).",
        );
        assert_overflow(
            |m| m.set_int32_i8(-129),
            "Value -129 for field 'int32_i8' is out of range for its packed bit-width of 8 bits (valid range is -128..=127).",
        );
        assert_overflow(
            |m| m.set_int32_i8(i32::MAX),
            "Value 2147483647 for field 'int32_i8' is out of range for its packed bit-width of 8 bits (valid range is -128..=127).",
        );
        assert_overflow(
            |m| m.set_int32_i8(i32::MIN),
            "Value -2147483648 for field 'int32_i8' is out of range for its packed bit-width of 8 bits (valid range is -128..=127).",
        );

        // int64_i8 (protobuf i64, packed i8)
        assert_overflow(
            |m| m.set_int64_i8(128),
            "Value 128 for field 'int64_i8' is out of range for its packed bit-width of 8 bits (valid range is -128..=127).",
        );
        assert_overflow(
            |m| m.set_int64_i8(-129),
            "Value -129 for field 'int64_i8' is out of range for its packed bit-width of 8 bits (valid range is -128..=127).",
        );
        assert_overflow(
            |m| m.set_int64_i8(i64::MAX),
            "Value 9223372036854775807 for field 'int64_i8' is out of range for its packed bit-width of 8 bits (valid range is -128..=127).",
        );
        assert_overflow(
            |m| m.set_int64_i8(i64::MIN),
            "Value -9223372036854775808 for field 'int64_i8' is out of range for its packed bit-width of 8 bits (valid range is -128..=127).",
        );

        // sfixed32_i8 (protobuf i32, packed i8)
        assert_overflow(
            |m| m.set_sfixed32_i8(128),
            "Value 128 for field 'sfixed32_i8' is out of range for its packed bit-width of 8 bits (valid range is -128..=127).",
        );
        assert_overflow(
            |m| m.set_sfixed32_i8(-129),
            "Value -129 for field 'sfixed32_i8' is out of range for its packed bit-width of 8 bits (valid range is -128..=127).",
        );
        assert_overflow(
            |m| m.set_sfixed32_i8(i32::MAX),
            "Value 2147483647 for field 'sfixed32_i8' is out of range for its packed bit-width of 8 bits (valid range is -128..=127).",
        );
        assert_overflow(
            |m| m.set_sfixed32_i8(i32::MIN),
            "Value -2147483648 for field 'sfixed32_i8' is out of range for its packed bit-width of 8 bits (valid range is -128..=127).",
        );

        // sint64_i8 (protobuf i64, packed i8)
        assert_overflow(
            |m| m.set_sint64_i8(128),
            "Value 128 for field 'sint64_i8' is out of range for its packed bit-width of 8 bits (valid range is -128..=127).",
        );
        assert_overflow(
            |m| m.set_sint64_i8(-129),
            "Value -129 for field 'sint64_i8' is out of range for its packed bit-width of 8 bits (valid range is -128..=127).",
        );
        assert_overflow(
            |m| m.set_sint64_i8(i64::MAX),
            "Value 9223372036854775807 for field 'sint64_i8' is out of range for its packed bit-width of 8 bits (valid range is -128..=127).",
        );
        assert_overflow(
            |m| m.set_sint64_i8(i64::MIN),
            "Value -9223372036854775808 for field 'sint64_i8' is out of range for its packed bit-width of 8 bits (valid range is -128..=127).",
        );

        // --- 8-bit Unsigned Fields (overflow and protobuf limits) ---

        // uint32_u8 (protobuf u32, packed u8)
        assert_overflow(
            |m| m.set_uint32_u8(256),
            "Value 256 for field 'uint32_u8' is out of range for its packed bit-width of 8 bits (valid range is 0..=255).",
        );
        assert_overflow(
            |m| m.set_uint32_u8(u32::MAX),
            "Value 4294967295 for field 'uint32_u8' is out of range for its packed bit-width of 8 bits (valid range is 0..=255).",
        );

        // fixed32_u8 (protobuf u32, packed u8)
        assert_overflow(
            |m| m.set_fixed32_u8(256),
            "Value 256 for field 'fixed32_u8' is out of range for its packed bit-width of 8 bits (valid range is 0..=255).",
        );
        assert_overflow(
            |m| m.set_fixed32_u8(u32::MAX),
            "Value 4294967295 for field 'fixed32_u8' is out of range for its packed bit-width of 8 bits (valid range is 0..=255).",
        );

        // uint64_u8 (protobuf u64, packed u8)
        assert_overflow(
            |m| m.set_uint64_u8(256),
            "Value 256 for field 'uint64_u8' is out of range for its packed bit-width of 8 bits (valid range is 0..=255).",
        );
        assert_overflow(
            |m| m.set_uint64_u8(u64::MAX),
            "Value 18446744073709551615 for field 'uint64_u8' is out of range for its packed bit-width of 8 bits (valid range is 0..=255).",
        );

        // --- 16-bit Signed Fields (overflow, underflow, and protobuf limits) ---

        // sint32_i16 (protobuf i32, packed i16)
        assert_overflow(
            |m| m.set_sint32_i16(32768),
            "Value 32768 for field 'sint32_i16' is out of range for its packed bit-width of 16 bits (valid range is -32768..=32767).",
        );
        assert_overflow(
            |m| m.set_sint32_i16(-32769),
            "Value -32769 for field 'sint32_i16' is out of range for its packed bit-width of 16 bits (valid range is -32768..=32767).",
        );
        assert_overflow(
            |m| m.set_sint32_i16(i32::MAX),
            "Value 2147483647 for field 'sint32_i16' is out of range for its packed bit-width of 16 bits (valid range is -32768..=32767).",
        );
        assert_overflow(
            |m| m.set_sint32_i16(i32::MIN),
            "Value -2147483648 for field 'sint32_i16' is out of range for its packed bit-width of 16 bits (valid range is -32768..=32767).",
        );

        // int32_i16 (protobuf i32, packed i16)
        assert_overflow(
            |m| m.set_int32_i16(32768),
            "Value 32768 for field 'int32_i16' is out of range for its packed bit-width of 16 bits (valid range is -32768..=32767).",
        );
        assert_overflow(
            |m| m.set_int32_i16(-32769),
            "Value -32769 for field 'int32_i16' is out of range for its packed bit-width of 16 bits (valid range is -32768..=32767).",
        );
        assert_overflow(
            |m| m.set_int32_i16(i32::MAX),
            "Value 2147483647 for field 'int32_i16' is out of range for its packed bit-width of 16 bits (valid range is -32768..=32767).",
        );
        assert_overflow(
            |m| m.set_int32_i16(i32::MIN),
            "Value -2147483648 for field 'int32_i16' is out of range for its packed bit-width of 16 bits (valid range is -32768..=32767).",
        );

        // int64_i16 (protobuf i64, packed i16)
        assert_overflow(
            |m| m.set_int64_i16(32768),
            "Value 32768 for field 'int64_i16' is out of range for its packed bit-width of 16 bits (valid range is -32768..=32767).",
        );
        assert_overflow(
            |m| m.set_int64_i16(-32769),
            "Value -32769 for field 'int64_i16' is out of range for its packed bit-width of 16 bits (valid range is -32768..=32767).",
        );
        assert_overflow(
            |m| m.set_int64_i16(i64::MAX),
            "Value 9223372036854775807 for field 'int64_i16' is out of range for its packed bit-width of 16 bits (valid range is -32768..=32767).",
        );
        assert_overflow(
            |m| m.set_int64_i16(i64::MIN),
            "Value -9223372036854775808 for field 'int64_i16' is out of range for its packed bit-width of 16 bits (valid range is -32768..=32767).",
        );

        // sfixed32_i16 (protobuf i32, packed i16)
        assert_overflow(
            |m| m.set_sfixed32_i16(32768),
            "Value 32768 for field 'sfixed32_i16' is out of range for its packed bit-width of 16 bits (valid range is -32768..=32767).",
        );
        assert_overflow(
            |m| m.set_sfixed32_i16(-32769),
            "Value -32769 for field 'sfixed32_i16' is out of range for its packed bit-width of 16 bits (valid range is -32768..=32767).",
        );
        assert_overflow(
            |m| m.set_sfixed32_i16(i32::MAX),
            "Value 2147483647 for field 'sfixed32_i16' is out of range for its packed bit-width of 16 bits (valid range is -32768..=32767).",
        );
        assert_overflow(
            |m| m.set_sfixed32_i16(i32::MIN),
            "Value -2147483648 for field 'sfixed32_i16' is out of range for its packed bit-width of 16 bits (valid range is -32768..=32767).",
        );

        // sint64_i16 (protobuf i64, packed i16)
        assert_overflow(
            |m| m.set_sint64_i16(32768),
            "Value 32768 for field 'sint64_i16' is out of range for its packed bit-width of 16 bits (valid range is -32768..=32767).",
        );
        assert_overflow(
            |m| m.set_sint64_i16(-32769),
            "Value -32769 for field 'sint64_i16' is out of range for its packed bit-width of 16 bits (valid range is -32768..=32767).",
        );
        assert_overflow(
            |m| m.set_sint64_i16(i64::MAX),
            "Value 9223372036854775807 for field 'sint64_i16' is out of range for its packed bit-width of 16 bits (valid range is -32768..=32767).",
        );
        assert_overflow(
            |m| m.set_sint64_i16(i64::MIN),
            "Value -9223372036854775808 for field 'sint64_i16' is out of range for its packed bit-width of 16 bits (valid range is -32768..=32767).",
        );

        // --- 16-bit Unsigned Fields (overflow and protobuf limits) ---

        // uint32_u16 (protobuf u32, packed u16)
        assert_overflow(
            |m| m.set_uint32_u16(65536),
            "Value 65536 for field 'uint32_u16' is out of range for its packed bit-width of 16 bits (valid range is 0..=65535).",
        );
        assert_overflow(
            |m| m.set_uint32_u16(u32::MAX),
            "Value 4294967295 for field 'uint32_u16' is out of range for its packed bit-width of 16 bits (valid range is 0..=65535).",
        );

        // fixed32_u16 (protobuf u32, packed u16)
        assert_overflow(
            |m| m.set_fixed32_u16(65536),
            "Value 65536 for field 'fixed32_u16' is out of range for its packed bit-width of 16 bits (valid range is 0..=65535).",
        );
        assert_overflow(
            |m| m.set_fixed32_u16(u32::MAX),
            "Value 4294967295 for field 'fixed32_u16' is out of range for its packed bit-width of 16 bits (valid range is 0..=65535).",
        );

        // uint64_u16 (protobuf u64, packed u16)
        assert_overflow(
            |m| m.set_uint64_u16(65536),
            "Value 65536 for field 'uint64_u16' is out of range for its packed bit-width of 16 bits (valid range is 0..=65535).",
        );
        assert_overflow(
            |m| m.set_uint64_u16(u64::MAX),
            "Value 18446744073709551615 for field 'uint64_u16' is out of range for its packed bit-width of 16 bits (valid range is 0..=65535).",
        );

        // --- 32-bit Signed Fields (overflow, underflow, and protobuf limits) ---

        // sint64_i32 (protobuf i64, packed i32)
        assert_overflow(
            |m| m.set_sint64_i32(2147483648),
            "Value 2147483648 for field 'sint64_i32' is out of range for its packed bit-width of 32 bits (valid range is -2147483648..=2147483647).",
        );
        assert_overflow(
            |m| m.set_sint64_i32(-2147483649),
            "Value -2147483649 for field 'sint64_i32' is out of range for its packed bit-width of 32 bits (valid range is -2147483648..=2147483647).",
        );
        assert_overflow(
            |m| m.set_sint64_i32(i64::MAX),
            "Value 9223372036854775807 for field 'sint64_i32' is out of range for its packed bit-width of 32 bits (valid range is -2147483648..=2147483647).",
        );
        assert_overflow(
            |m| m.set_sint64_i32(i64::MIN),
            "Value -9223372036854775808 for field 'sint64_i32' is out of range for its packed bit-width of 32 bits (valid range is -2147483648..=2147483647).",
        );

        // int64_i32 (protobuf i64, packed i32)
        assert_overflow(
            |m| m.set_int64_i32(2147483648),
            "Value 2147483648 for field 'int64_i32' is out of range for its packed bit-width of 32 bits (valid range is -2147483648..=2147483647).",
        );
        assert_overflow(
            |m| m.set_int64_i32(-2147483649),
            "Value -2147483649 for field 'int64_i32' is out of range for its packed bit-width of 32 bits (valid range is -2147483648..=2147483647).",
        );
        assert_overflow(
            |m| m.set_int64_i32(i64::MAX),
            "Value 9223372036854775807 for field 'int64_i32' is out of range for its packed bit-width of 32 bits (valid range is -2147483648..=2147483647).",
        );
        assert_overflow(
            |m| m.set_int64_i32(i64::MIN),
            "Value -9223372036854775808 for field 'int64_i32' is out of range for its packed bit-width of 32 bits (valid range is -2147483648..=2147483647).",
        );

        // --- 32-bit Unsigned Fields (overflow and protobuf limits) ---

        // uint64_u32 (protobuf u64, packed u32)
        assert_overflow(
            |m| m.set_uint64_u32(4294967296),
            "Value 4294967296 for field 'uint64_u32' is out of range for its packed bit-width of 32 bits (valid range is 0..=4294967295).",
        );
        assert_overflow(
            |m| m.set_uint64_u32(u64::MAX),
            "Value 18446744073709551615 for field 'uint64_u32' is out of range for its packed bit-width of 32 bits (valid range is 0..=4294967295).",
        );
    }
}
