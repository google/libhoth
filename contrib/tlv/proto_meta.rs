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

use descriptor_rust_proto::DescriptorProtoView;
use descriptor_rust_proto::FieldDescriptorProtoView;
use openprot_proto_reader::ProtoReader;
use openprot_proto_reader::Record;
use openprot_proto_reflect::TypeExt;
use protobuf::Parse;
use protobuf::Serialize;

const TLV_FOURCC_OPTION_NUMBER: u32 = 12345;
const BIT_PACKED_OPTION_NUMBER: u32 = 12346;

const OFFSET_OPTION_NUMBER: u32 = 12345;
const TYPE_OPTION_NUMBER: u32 = 12346;
const BIT_RANGE_OPTION_NUMBER: u32 = 12347;
const EXTRA_DATA_OPTION_NUMBER: u32 = 12348;

pub use ::protobuf::__internal::runtime::__unstable::DescriptorInfo;
/// Re-export the Type enum so clients of proto_meta can easily use it.
pub use descriptor_rust_proto::field_descriptor_proto::Type;

/// Recursively parses a `DescriptorInfo` dependency tree into a strongly-typed `FileDescriptorSet`.
pub fn collect_descriptor_set(
    info: &DescriptorInfo,
) -> Option<descriptor_rust_proto::FileDescriptorSet> {
    fn inner(
        info: &DescriptorInfo,
        set: &mut descriptor_rust_proto::FileDescriptorSet,
        visited: &mut std::collections::HashSet<*const DescriptorInfo>,
    ) -> Option<()> {
        let ptr = info as *const _;
        if !visited.insert(ptr) {
            return Some(());
        }

        let file_proto = descriptor_rust_proto::FileDescriptorProto::parse(info.descriptor).ok()?;
        set.file_mut().push(file_proto);

        for dep in info.deps {
            inner(dep, set, visited)?;
        }
        Some(())
    }

    let mut set = descriptor_rust_proto::FileDescriptorSet::new();
    let mut visited = std::collections::HashSet::new();
    inner(info, &mut set, &mut visited)?;
    Some(set)
}

pub trait NameStrExt {
    fn name_str(&self) -> &str;
}

impl<'a> NameStrExt for FieldDescriptorProtoView<'a> {
    fn name_str(&self) -> &str {
        self.name().to_str().unwrap_or("<unknown>")
    }
}

impl<'a> NameStrExt for DescriptorProtoView<'a> {
    fn name_str(&self) -> &str {
        self.name().to_str().unwrap_or("<unknown>")
    }
}

pub trait DescriptorProtoExt<'a> {
    fn find_field(&self, field_number: u32) -> Option<FieldDescriptorProtoView<'a>>;
}

impl<'a> DescriptorProtoExt<'a> for DescriptorProtoView<'a> {
    fn find_field(&self, field_number: u32) -> Option<FieldDescriptorProtoView<'a>> {
        self.field()
            .into_iter()
            .find(|f| f.number() as u32 == field_number)
    }
}

/// The backing integer type of a bit-packed message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BackingType {
    U8,
    U16,
    U32,
}

impl BackingType {
    /// Returns the size in bytes of the backing type.
    pub fn size(&self) -> usize {
        match self {
            Self::U8 => 1,
            Self::U16 => 2,
            Self::U32 => 4,
        }
    }

    /// Returns the width in bits of the backing type.
    pub fn bits(&self) -> usize {
        self.size() * 8
    }
}

/// A strongly-typed sub-field bit layout within a bit-packed message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BitPackedField {
    /// The bit offset within the bit-packed message.
    pub bit_offset: usize,
    /// The bit length of the field.
    pub bit_len: usize,
}

/// The specific kind of layout violation that occurred.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlvLayoutErrorKind {
    /// The field has an invalid type option value.
    InvalidTypeOption {
        /// The invalid type option string specified.
        value: String,
    },
    /// The packable primitive field is missing a custom offset option.
    MissingOffset {
        /// The Protobuf type of the field.
        kind: Type,
    },
    /// The string or bytes field has a custom offset but is missing an explicit type option.
    MissingTypeOption {
        /// The Protobuf type of the field.
        kind: Type,
        /// The custom offset specified on the field.
        offset: usize,
    },
    /// The field type is not supported for TLV layout (only packable primitives, inline strings/bytes, and nested messages are supported).
    UnsupportedFieldType {
        /// The Protobuf type of the field.
        kind: Type,
    },
    /// The field's custom offset is not naturally aligned to its size/alignment.
    UnalignedOffset {
        /// The offset specified.
        offset: usize,
        /// The alignment/size of the field.
        size: usize,
    },
    /// A field in a bit-packed message is missing the required `bit_range` option.
    MissingBitRange,
    /// A field in a bit-packed message specified a custom `offset` or `type` (not allowed, packing is sequential).
    OffsetOrTypeInBitPacked,
    /// The `bit_range` option was specified on a non-packable field type.
    BitRangeOnNonPackableType {
        /// The Protobuf type of the field.
        kind: Type,
    },
    /// The `bit_range` option has an invalid format (must be "[high:low]").
    InvalidBitRangeFormat {
        /// The invalid value specified.
        value: String,
    },
    /// The `bit_range` option has high bit less than low bit.
    InvalidBitRangeOrder {
        /// The high bit specified.
        high: usize,
        /// The low bit specified.
        low: usize,
    },
    /// The `bit_range` high bit is out of bounds for the backing register width.
    BitRangeOutOfBounds {
        /// The high bit specified.
        high: usize,
        /// The maximum bits allowed by the backing type.
        max_bits: usize,
    },
    /// Two or more fields overlap in their bit ranges.
    OverlappingBits {
        /// The name of the first field.
        field_a: String,
        /// The name of the second field.
        field_b: String,
        /// The bit range of the first field.
        range_a: std::ops::RangeInclusive<usize>,
        /// The bit range of the second field.
        range_b: std::ops::RangeInclusive<usize>,
    },
    /// The `bit_packed` option has an invalid string value (must be "u8", "u16", or "u32").
    InvalidBitPackedType {
        /// The invalid value specified.
        value: String,
    },
    /// A nested message field has a custom `offset` but its type is not packable inline.
    NestedMessageNotPackable {
        /// The name of the nested message type.
        type_name: String,
    },
    /// A bit-packed nested message field is missing a custom `offset` option (cannot be serialized as a dynamic sub-TLV).
    BitPackedCannotBeTlv {
        /// The name of the nested message type.
        type_name: String,
    },
    /// A bit-packed message specified a `tlv_fourcc` option (not allowed, bit-packed messages are raw registers with no TLV header).
    BitPackedCannotHaveFourcc,
    /// A nested message type descriptor was not found in the descriptor set.
    NestedMessageNotFound {
        /// The name of the nested message type.
        type_name: String,
    },
    /// Two or more fields overlap in their byte ranges in the fixed struct.
    OverlappingFields {
        /// The name of the first field.
        field_a: String,
        /// The name of the second field.
        field_b: String,
        /// The byte range of the first field.
        range_a: std::ops::Range<usize>,
        /// The byte range of the second field.
        range_b: std::ops::Range<usize>,
    },
    /// The string or bytes field has an explicit size override of 0 (must be greater than 0).
    ZeroSizeStringOrBytes,
    /// Standalone boolean fields are not supported in standard TLV structures.
    StandaloneBoolNotSupported,
    /// The signedness of the Protobuf field type does not match the signedness of the custom TLV type option.
    SignednessMismatch {
        /// The Protobuf type of the field.
        proto_type: Type,
        /// The custom type option string specified.
        value: String,
    },
    /// The float/integer nature of the Protobuf field type does not match the custom TLV type option.
    FloatIntegerMismatch {
        /// The Protobuf type of the field.
        proto_type: Type,
        /// The custom type option string specified.
        value: String,
    },
    /// A repeated field is not allowed to have a custom `offset` option.
    RepeatedFieldCannotHaveOffset,
    /// A field inside a `oneof` is not allowed to have a custom `offset` option.
    OneofFieldCannotHaveOffset,
    /// A nested message acting as a dynamic sub-TLV is missing the `tlv_fourcc` option.
    MissingTlvFourcc {
        /// The name of the nested message type.
        type_name: String,
    },
    /// Two or more sub-TLV fields in the same message share the same tlv_fourcc tag.
    DuplicateTlvTag {
        /// The duplicated 4-character tag.
        tag: [u8; 4],
        /// The name of the first field.
        field_a: String,
        /// The name of the second field.
        field_b: String,
    },
    /// A circular dependency was detected in the inline nested message layout.
    CircularDependency {
        /// The name of the message that triggered the cycle.
        type_name: String,
    },
    /// A field with `extra_data` option specified an explicit `offset` option.
    ExtraDataWithOffset,
    /// A field with `extra_data` option is missing an explicit `type` option.
    ExtraDataMissingTypeOption,
    /// A field with `extra_data` option specified an unsupported `type` option value.
    ExtraDataUnsupportedType {
        /// The invalid type option string specified.
        value: String,
    },
    /// A field with `extra_data` option is not a string or bytes field.
    ExtraDataOnNonStringOrBytes {
        /// The Protobuf type of the field.
        kind: Type,
    },
    /// Multiple fields in the same message specified the `extra_data` option.
    MultipleExtraDataFields,
    /// A message contains both an `extra_data` field and dynamic sub-TLVs.
    ExtraDataWithSubTlvs,
    /// A repeated field specified the `extra_data` option.
    RepeatedFieldCannotHaveExtraData,
    /// A field inside a `oneof` specified the `extra_data` option.
    OneofFieldCannotHaveExtraData,
}

struct VerilogRange(std::ops::RangeInclusive<usize>);

impl std::fmt::Display for VerilogRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (low, high) = (*self.0.start(), *self.0.end());
        if high == low {
            write!(f, "{}", low)
        } else {
            write!(f, "{}:{}", high, low)
        }
    }
}

impl std::fmt::Display for TlvLayoutErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidTypeOption { value } => {
                write!(
                    f,
                    "explicit type option must be a valid Rust type (got '{}').",
                    value
                )
            }
            Self::MissingOffset { kind } => {
                write!(
                    f,
                    "primitive field of type '{:?}' is missing a custom 'offset' option. All primitive fields in a TLV-serializable message must be packed in the fixed struct.",
                    kind
                )
            }
            Self::MissingTypeOption { kind, offset } => {
                write!(
                    f,
                    "field of type '{:?}' has a custom offset ({}) but is missing an explicit 'type' option. Inline strings or byte arrays in the fixed struct must specify an explicit type.",
                    kind, offset
                )
            }
            Self::UnsupportedFieldType { kind } => {
                write!(
                    f,
                    "Protobuf type '{:?}' is not supported for TLV layout (only packable primitives, inline strings/bytes, and nested sub-messages are supported).",
                    kind
                )
            }
            Self::UnalignedOffset { offset, size } => {
                write!(
                    f,
                    "offset of {} is not naturally aligned to its size of {} bytes (offset must be a multiple of size).",
                    offset, size
                )
            }
            Self::MissingBitRange => {
                write!(
                    f,
                    "field in a bit-packed message is missing the required 'bit_range' option."
                )
            }
            Self::OffsetOrTypeInBitPacked => {
                write!(
                    f,
                    "field in a bit-packed message is not allowed to specify 'offset' or 'type' options; use the 'bit_range' option to specify its position."
                )
            }
            Self::BitRangeOnNonPackableType { kind } => {
                write!(
                    f,
                    "bit_range option is only supported on packable primitive integer, enum, or boolean types (got '{:?}').",
                    kind
                )
            }
            Self::InvalidBitRangeFormat { value } => {
                write!(
                    f,
                    "invalid bit_range format: '{}' (must be Verilog notation like 'high:low').",
                    value
                )
            }
            Self::InvalidBitRangeOrder { high, low } => {
                write!(
                    f,
                    "invalid bit_range order '{}:{}': high bit must be greater than or equal to low bit.",
                    high, low
                )
            }
            Self::BitRangeOutOfBounds { high, max_bits } => {
                write!(
                    f,
                    "bit_range high bit {} is out of bounds for the backing register width of {} bits.",
                    high, max_bits
                )
            }
            Self::OverlappingBits {
                field_a,
                field_b,
                range_a,
                range_b,
            } => {
                write!(
                    f,
                    "field '{}' (bits {}) overlaps with field '{}' (bits {}) in the bit-packed register.",
                    field_a,
                    VerilogRange(range_a.clone()),
                    field_b,
                    VerilogRange(range_b.clone())
                )
            }
            Self::InvalidBitPackedType { value } => {
                write!(
                    f,
                    "invalid value for 'bit_packed' option: '{}' (must be 'u8', 'u16', or 'u32').",
                    value
                )
            }
            Self::NestedMessageNotPackable { type_name } => {
                write!(
                    f,
                    "nested message field has a custom offset but its type '{}' is not packable inline (it must be bit-packed or a standard struct with no dynamic sub-TLVs).",
                    type_name
                )
            }
            Self::BitPackedCannotBeTlv { type_name } => {
                write!(
                    f,
                    "bit-packed message of type '{}' cannot be serialized as a dynamic sub-TLV; it must be packed inline inside the fixed struct using a custom 'offset' option.",
                    type_name
                )
            }
            Self::BitPackedCannotHaveFourcc => {
                write!(
                    f,
                    "message is bit-packed and cannot specify a 'tlv_fourcc' option; bit-packed messages are raw registers and cannot be serialized as TLV blocks."
                )
            }
            Self::MissingTlvFourcc { type_name } => {
                write!(
                    f,
                    "nested message '{}' acts as a dynamic sub-TLV but is missing a 'tlv_fourcc' option; sub-TLVs must have a unique 4-character tag.",
                    type_name
                )
            }
            Self::DuplicateTlvTag {
                tag,
                field_a,
                field_b,
            } => {
                let tag_str = String::from_utf8_lossy(tag).into_owned();
                write!(
                    f,
                    "sub-TLV fields '{}' and '{}' share the same tlv_fourcc tag '{}'; all sub-TLV fields within a message must have unique tags to prevent decoding ambiguity.",
                    field_a, field_b, tag_str
                )
            }
            Self::CircularDependency { type_name } => {
                write!(
                    f,
                    "circular dependency detected: message '{}' directly or indirectly contains itself inline, which requires infinite struct size.",
                    type_name
                )
            }
            Self::NestedMessageNotFound { type_name } => {
                write!(
                    f,
                    "nested message type descriptor for '{}' was not found in the descriptor set.",
                    type_name
                )
            }
            Self::OverlappingFields {
                field_a,
                field_b,
                range_a,
                range_b,
            } => {
                write!(
                    f,
                    "field '{}' (bytes {}..{}) overlaps with field '{}' (bytes {}..{}) in the fixed struct.",
                    field_a, range_a.start, range_a.end, field_b, range_b.start, range_b.end
                )
            }
            Self::ZeroSizeStringOrBytes => {
                write!(
                    f,
                    "explicit size option for inline string or bytes fields must be greater than 0."
                )
            }
            Self::StandaloneBoolNotSupported => {
                write!(
                    f,
                    "standalone boolean fields are not supported because they cannot be safely decoded via zero-copy. Use a custom 'type' option to map the field to an integer type (e.g. `[(openprot.tlv.type) = \"u8\"]`), or place the field inside a bit-packed message (using `option (openprot.tlv.bit_packed) = ...;`)."
                )
            }
            Self::SignednessMismatch { proto_type, value } => {
                let proto_info = proto_type.primitive_info().unwrap();
                let proto_signed_str = if proto_info.is_signed {
                    "signed"
                } else {
                    "unsigned"
                };

                let parsed_type = PackedType::parse(value).unwrap();
                let packed_signed_str = if parsed_type.is_signed() {
                    "signed"
                } else {
                    "unsigned"
                };

                let suggestion = if proto_info.is_signed {
                    "Signed Protobuf fields must be mapped to signed Rust types (e.g. i8, i16, i32, i64)."
                } else {
                    "Unsigned Protobuf fields must be mapped to unsigned Rust types (e.g. u8, u16, u32, u64)."
                };

                write!(
                    f,
                    "signedness mismatch: Protobuf field type '{:?}' ({}) does not match the signedness of the custom TLV type '{}' ({}). {}",
                    proto_type, proto_signed_str, value, packed_signed_str, suggestion
                )
            }
            Self::FloatIntegerMismatch { proto_type, value } => {
                let proto_info = proto_type.primitive_info().unwrap();
                let proto_str = if proto_info.is_float {
                    "floating-point"
                } else {
                    "integer"
                };

                let parsed_type = PackedType::parse(value).unwrap();
                let packed_str = if parsed_type.is_float() {
                    "floating-point"
                } else {
                    "integer"
                };

                let suggestion = if proto_info.is_float {
                    "Floating-point Protobuf fields must be mapped to floating-point Rust types (f32, f64)."
                } else {
                    "Integer Protobuf fields must be mapped to integer Rust types (e.g. i8, u8, i16, u16, i32, u32, i64, u64)."
                };

                write!(
                    f,
                    "type mismatch: Protobuf field type '{:?}' ({}) does not match the custom TLV type '{}' ({}). {}",
                    proto_type, proto_str, value, packed_str, suggestion
                )
            }
            Self::RepeatedFieldCannotHaveOffset => {
                write!(
                    f,
                    "repeated fields are not allowed to specify a custom 'offset' option because their size is dynamic. They must be serialized as dynamic sub-TLVs (omit the 'offset' option)."
                )
            }
            Self::OneofFieldCannotHaveOffset => {
                write!(
                    f,
                    "fields inside a 'oneof' are not allowed to specify a custom 'offset' option because they are mutually exclusive. They must be serialized as dynamic sub-TLVs (omit the 'offset' option)."
                )
            }
            Self::ExtraDataWithOffset => {
                write!(
                    f,
                    "field with 'extra_data' option cannot specify a custom 'offset' option."
                )
            }
            Self::ExtraDataMissingTypeOption => {
                write!(
                    f,
                    "field with 'extra_data' option must explicitly specify a 'type' option (e.g., `[(openprot.tlv.type) = \"[u8]\"]`)."
                )
            }
            Self::ExtraDataUnsupportedType { value } => {
                write!(
                    f,
                    "'extra_data' option currently only supports type '[u8]' (got '{}').",
                    value
                )
            }
            Self::ExtraDataOnNonStringOrBytes { kind } => {
                write!(
                    f,
                    "'extra_data' option is only supported on 'string' or 'bytes' fields (got '{:?}').",
                    kind
                )
            }
            Self::MultipleExtraDataFields => {
                write!(
                    f,
                    "message cannot have more than one field with 'extra_data' option."
                )
            }
            Self::ExtraDataWithSubTlvs => {
                write!(
                    f,
                    "message with an 'extra_data' field cannot also contain dynamic sub-TLVs."
                )
            }
            Self::RepeatedFieldCannotHaveExtraData => {
                write!(f, "field with 'extra_data' option cannot be 'repeated'.")
            }
            Self::OneofFieldCannotHaveExtraData => {
                write!(
                    f,
                    "field with 'extra_data' option cannot be inside a 'oneof'."
                )
            }
        }
    }
}

/// A structured, strongly-typed layout error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlvLayoutError {
    /// The name of the message where the error occurred.
    pub message_name: String,
    /// The name of the field where the error occurred, if applicable.
    pub field_name: Option<String>,
    /// The specific kind of layout violation.
    pub kind: TlvLayoutErrorKind,
}

impl std::fmt::Display for TlvLayoutError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(field_name) = &self.field_name {
            write!(
                f,
                "Invalid TLV layout on field '{}' of message '{}': {}",
                field_name, self.message_name, self.kind
            )
        } else {
            write!(
                f,
                "Invalid TLV layout in message '{}': {}",
                self.message_name, self.kind
            )
        }
    }
}

impl std::error::Error for TlvLayoutError {}

/// The layout and serialization strategy for a field in the TLV representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldLayout {
    /// The field is packed into the fixed struct at a specific offset and size in bytes.
    Fixed {
        /// The byte offset of the field in the fixed TLV struct.
        offset: usize,
        /// The resolved packed type representation of the field.
        packed_type: PackedType,
    },
    /// The field is serialized as a dynamically appended sub-TLV.
    Tlv {
        /// The underlying Protobuf type of the field.
        kind: Type,
        /// The 4-character TLV tag.
        tag: [u8; 4],
    },
    /// The field is stored as the unpadded raw extra data payload of the TLV record.
    ExtraData,
}

/// Fully resolved and validated TLV layout for a message descriptor.
#[derive(Debug, Clone)]
pub enum TlvLayout {
    /// A standard TLV message with a byte-aligned fixed struct and optional dynamic sub-TLVs.
    Standard {
        /// Mapping of field numbers to their resolved `FieldLayout`s.
        fields: std::collections::HashMap<u32, FieldLayout>,
        /// The total resolved size in bytes of the fixed struct portion of the message.
        fixed_struct_size: usize,
    },
    /// A bit-packed message where all fields are packed sequentially at the bit level.
    BitPacked {
        /// Mapping of field numbers to their resolved `BitPackedField` metadata.
        fields: std::collections::HashMap<u32, BitPackedField>,
        /// The backing integer type of the bit-packed message.
        backing: BackingType,
    },
}

impl TlvLayout {
    /// Returns the total resolved size in bytes of the fixed struct/body.
    pub fn fixed_struct_size(&self) -> usize {
        match self {
            Self::Standard {
                fixed_struct_size, ..
            } => *fixed_struct_size,
            Self::BitPacked { backing, .. } => backing.size(),
        }
    }
}

/// Extension trait providing convenient access to TLV custom options on message descriptors.
pub trait DescriptorProtoTlvExt {
    /// Returns the `tlv_fourcc` custom option value of this message as a 4-byte array, if present.
    fn tlv_fourcc(&self) -> Option<[u8; 4]>;

    /// Returns the parsed `bit_packed` custom option of this message, if present.
    #[allow(clippy::result_large_err)]
    fn bit_packed(&self) -> Result<Option<BackingType>, TlvLayoutError>;

    /// Resolves and validates the entire `TlvLayout` for this message descriptor.
    #[allow(clippy::result_large_err)]
    fn tlv_layout(
        &self,
        desc_set: &descriptor_rust_proto::FileDescriptorSet,
    ) -> Result<TlvLayout, TlvLayoutError>;

    /// Resolves and validates the entire `TlvLayout` for this message descriptor using a custom name path.
    #[allow(clippy::result_large_err)]
    fn tlv_layout_with_name(
        &self,
        full_name: &str,
        desc_set: &descriptor_rust_proto::FileDescriptorSet,
    ) -> Result<TlvLayout, TlvLayoutError>;
}

impl<'a> DescriptorProtoTlvExt for DescriptorProtoView<'a> {
    fn tlv_fourcc(&self) -> Option<[u8; 4]> {
        let opt_bytes = self.options().serialize().ok()?;
        let reader = ProtoReader::new(&opt_bytes);
        match reader.find_field(TLV_FOURCC_OPTION_NUMBER) {
            Some(Record::LengthDelimited(bytes)) => {
                if bytes.len() == 4 {
                    let mut tag = [0u8; 4];
                    tag.copy_from_slice(bytes);
                    Some(tag)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    #[allow(clippy::result_large_err)]
    fn bit_packed(&self) -> Result<Option<BackingType>, TlvLayoutError> {
        let opt_bytes = match self.options().serialize() {
            Ok(bytes) => bytes,
            Err(_) => return Ok(None),
        };
        let reader = ProtoReader::new(&opt_bytes);
        match reader.find_field(BIT_PACKED_OPTION_NUMBER) {
            Some(Record::LengthDelimited(bytes)) => {
                if bytes == b"u8" {
                    Ok(Some(BackingType::U8))
                } else if bytes == b"u16" {
                    Ok(Some(BackingType::U16))
                } else if bytes == b"u32" {
                    Ok(Some(BackingType::U32))
                } else {
                    let invalid_str = String::from_utf8_lossy(bytes).into_owned();
                    Err(TlvLayoutError {
                        message_name: self.name_str().to_string(),
                        field_name: None,
                        kind: TlvLayoutErrorKind::InvalidBitPackedType { value: invalid_str },
                    })
                }
            }
            _ => Ok(None),
        }
    }

    fn tlv_layout(
        &self,
        desc_set: &descriptor_rust_proto::FileDescriptorSet,
    ) -> Result<TlvLayout, TlvLayoutError> {
        self.tlv_layout_with_name(self.name_str(), desc_set)
    }

    fn tlv_layout_with_name(
        &self,
        full_name: &str,
        desc_set: &descriptor_rust_proto::FileDescriptorSet,
    ) -> Result<TlvLayout, TlvLayoutError> {
        let mut active_resolves = std::collections::HashSet::new();
        tlv_layout_rec(self, full_name, desc_set, &mut active_resolves)
    }
}

const RAW_TYPE_OPTION_NUMBER: u32 = 12345;

/// Extension trait providing convenient access to TLV custom options on enum descriptors.
pub trait EnumDescriptorProtoTlvExt {
    /// Returns the `raw_type` custom option value of this enum, if present.
    fn raw_type(&self) -> Option<String>;
}

impl<'a> EnumDescriptorProtoTlvExt for descriptor_rust_proto::EnumDescriptorProtoView<'a> {
    fn raw_type(&self) -> Option<String> {
        let opt_bytes = self.options().serialize().ok()?;
        let reader = ProtoReader::new(&opt_bytes);
        match reader.find_field(RAW_TYPE_OPTION_NUMBER) {
            Some(Record::LengthDelimited(bytes)) => String::from_utf8(bytes.to_vec()).ok(),
            _ => None,
        }
    }
}

#[allow(clippy::result_large_err)]
fn tlv_layout_rec(
    msg: &DescriptorProtoView<'_>,
    full_name: &str,
    desc_set: &descriptor_rust_proto::FileDescriptorSet,
    active_resolves: &mut std::collections::HashSet<String>,
) -> Result<TlvLayout, TlvLayoutError> {
    let msg_name = msg.name_str().to_string();
    if !active_resolves.insert(full_name.to_string()) {
        return Err(TlvLayoutError {
            message_name: msg_name.clone(),
            field_name: None,
            kind: TlvLayoutErrorKind::CircularDependency {
                type_name: full_name.to_string(),
            },
        });
    }

    let bit_packed_opt = msg.bit_packed()?;

    let res = if let Some(backing) = bit_packed_opt {
        // Validate that a bit-packed message does NOT have a tlv_fourcc option!
        if msg.tlv_fourcc().is_some() {
            return Err(TlvLayoutError {
                message_name: msg_name.clone(),
                field_name: None,
                kind: TlvLayoutErrorKind::BitPackedCannotHaveFourcc,
            });
        }

        let mod_fields = &backing; // Wait, to avoid shadowing
        let mut fields = std::collections::HashMap::new();
        let mut bit_ranges_collected = Vec::new();

        for field in msg.field() {
            let field_number = field.number() as u32;
            let kind = field.r#type();
            let field_name = field.name_str().to_string();

            // Validate no offset or type options on bit-packed fields
            if field.offset().is_some() || field.type_option().is_some() {
                return Err(TlvLayoutError {
                    message_name: msg_name.clone(),
                    field_name: Some(field_name),
                    kind: TlvLayoutErrorKind::OffsetOrTypeInBitPacked,
                });
            }

            // Validate type is a packable primitive (integers, enums, and booleans only!)
            if kind.primitive_info().is_none_or(|info| info.is_float) {
                return Err(TlvLayoutError {
                    message_name: msg_name.clone(),
                    field_name: Some(field_name),
                    kind: TlvLayoutErrorKind::BitRangeOnNonPackableType { kind },
                });
            }

            let bit_range = match field.bit_range() {
                Some(r) => r,
                None => {
                    return Err(TlvLayoutError {
                        message_name: msg_name.clone(),
                        field_name: Some(field_name),
                        kind: TlvLayoutErrorKind::MissingBitRange,
                    });
                }
            };

            let Some(range) = parse_verilog_bit_range(&bit_range) else {
                return Err(TlvLayoutError {
                    message_name: msg_name.clone(),
                    field_name: Some(field_name),
                    kind: TlvLayoutErrorKind::InvalidBitRangeFormat { value: bit_range },
                });
            };

            let (high, low) = (*range.end(), *range.start());
            if high < low {
                return Err(TlvLayoutError {
                    message_name: msg_name.clone(),
                    field_name: Some(field_name),
                    kind: TlvLayoutErrorKind::InvalidBitRangeOrder { high, low },
                });
            }

            if high >= mod_fields.bits() {
                return Err(TlvLayoutError {
                    message_name: msg_name.clone(),
                    field_name: Some(field_name),
                    kind: TlvLayoutErrorKind::BitRangeOutOfBounds {
                        high,
                        max_bits: mod_fields.bits(),
                    },
                });
            }

            let bit_len = high - low + 1;
            fields.insert(
                field_number,
                BitPackedField {
                    bit_offset: low,
                    bit_len,
                },
            );

            bit_ranges_collected.push((range, field_name));
        }

        // Validate bit-level overlapping fields
        bit_ranges_collected.sort_by_key(|r| *r.0.start());
        for i in 1..bit_ranges_collected.len() {
            let prev = &bit_ranges_collected[i - 1];
            let curr = &bit_ranges_collected[i];

            if *curr.0.start() <= *prev.0.end() {
                return Err(TlvLayoutError {
                    message_name: msg_name.clone(),
                    field_name: None,
                    kind: TlvLayoutErrorKind::OverlappingBits {
                        field_a: prev.1.clone(),
                        field_b: curr.1.clone(),
                        range_a: prev.0.clone(),
                        range_b: curr.0.clone(),
                    },
                });
            }
        }

        Ok(TlvLayout::BitPacked { fields, backing })
    } else {
        // --- 2. Resolve Standard Message Layout ---
        let mut fields = std::collections::HashMap::new();
        let mut fixed_fields_ranges = Vec::new();
        let mut max_offset_plus_size = 0;
        let mut tag_to_field = std::collections::HashMap::new();

        let mut extra_data_count = 0;
        let mut tlv_count = 0;

        for field in msg.field() {
            let field_number = field.number() as u32;
            let layout =
                field_tlv_layout_rec(&field, desc_set, active_resolves).map_err(|kind| {
                    TlvLayoutError {
                        message_name: msg_name.clone(),
                        field_name: Some(field.name_str().to_string()),
                        kind,
                    }
                })?;

            if matches!(layout, FieldLayout::ExtraData) {
                extra_data_count += 1;
            }
            if matches!(layout, FieldLayout::Tlv { .. }) {
                tlv_count += 1;
            }

            if let FieldLayout::Tlv { tag, .. } = &layout {
                let field_name = field.name_str().to_string();
                if let Some(prev_field) = tag_to_field.insert(*tag, field_name.clone()) {
                    return Err(TlvLayoutError {
                        message_name: msg_name.clone(),
                        field_name: None,
                        kind: TlvLayoutErrorKind::DuplicateTlvTag {
                            tag: *tag,
                            field_a: prev_field,
                            field_b: field_name,
                        },
                    });
                }
            }

            if let FieldLayout::Fixed {
                offset,
                packed_type,
            } = &layout
            {
                let size = packed_type.size();
                fixed_fields_ranges.push((*offset..*offset + size, field.name_str().to_string()));

                if *offset + size > max_offset_plus_size {
                    max_offset_plus_size = *offset + size;
                }
            }
            fields.insert(field_number, layout);
        }

        if extra_data_count > 1 {
            return Err(TlvLayoutError {
                message_name: msg_name.clone(),
                field_name: None,
                kind: TlvLayoutErrorKind::MultipleExtraDataFields,
            });
        }
        if extra_data_count > 0 && tlv_count > 0 {
            return Err(TlvLayoutError {
                message_name: msg_name.clone(),
                field_name: None,
                kind: TlvLayoutErrorKind::ExtraDataWithSubTlvs,
            });
        }

        // Validate overlapping fields
        fixed_fields_ranges.sort_by_key(|r| r.0.start);
        for i in 1..fixed_fields_ranges.len() {
            let prev = &fixed_fields_ranges[i - 1];
            let curr = &fixed_fields_ranges[i];

            if curr.0.start < prev.0.end {
                return Err(TlvLayoutError {
                    message_name: msg_name.clone(),
                    field_name: None,
                    kind: TlvLayoutErrorKind::OverlappingFields {
                        field_a: prev.1.clone(),
                        field_b: curr.1.clone(),
                        range_a: prev.0.clone(),
                        range_b: curr.0.clone(),
                    },
                });
            }
        }

        let fixed_struct_size = (max_offset_plus_size + 3) & !3;
        Ok(TlvLayout::Standard {
            fields,
            fixed_struct_size,
        })
    };

    active_resolves.remove(full_name);
    res
}

/// Helper to parse Verilog bit range format like "7:0" (multi-bit) or "0" (single-bit) into a RangeInclusive.
fn parse_verilog_bit_range(s: &str) -> Option<std::ops::RangeInclusive<usize>> {
    let s = s.trim();
    if s.contains(':') {
        let mut parts = s.split(':');
        let high_str = parts.next()?;
        let low_str = parts.next()?;
        if parts.next().is_some() {
            return None;
        }
        let high = high_str.trim().parse::<usize>().ok()?;
        let low = low_str.trim().parse::<usize>().ok()?;
        Some(low..=high)
    } else {
        let bit = s.parse::<usize>().ok()?;
        Some(bit..=bit)
    }
}

/// The primitive types supported in a packed struct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackedPrimitiveType {
    U8,
    U16,
    U32,
    U64,
    I8,
    I16,
    I32,
    I64,
    F32,
    F64,
    Bool,
}

impl PackedPrimitiveType {
    /// Parses a primitive type from a string.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "u8" => Some(Self::U8),
            "u16" => Some(Self::U16),
            "u32" => Some(Self::U32),
            "u64" => Some(Self::U64),
            "i8" => Some(Self::I8),
            "i16" => Some(Self::I16),
            "i32" => Some(Self::I32),
            "i64" => Some(Self::I64),
            "f32" => Some(Self::F32),
            "f64" => Some(Self::F64),
            "bool" => Some(Self::Bool),
            _ => None,
        }
    }

    /// Returns the size in bytes of the primitive type.
    pub fn size(&self) -> usize {
        match self {
            Self::U8 | Self::I8 | Self::Bool => 1,
            Self::U16 | Self::I16 => 2,
            Self::U32 | Self::I32 | Self::F32 => 4,
            Self::U64 | Self::I64 | Self::F64 => 8,
        }
    }

    /// Returns whether the primitive type is signed.
    pub fn is_signed(&self) -> bool {
        match self {
            Self::I8 | Self::I16 | Self::I32 | Self::I64 | Self::F32 | Self::F64 => true,
            Self::U8 | Self::U16 | Self::U32 | Self::U64 | Self::Bool => false,
        }
    }

    /// Returns true if this primitive is a floating point type.
    pub fn is_float(&self) -> bool {
        matches!(self, Self::F32 | Self::F64)
    }

    /// Returns the alignment in bytes of the primitive type.
    pub fn alignment(&self) -> usize {
        // 64-bit primitives are mapped to 4-aligned wrapper types in codegen,
        // so their layout alignment requirement is at most 4 bytes.
        std::cmp::min(self.size(), 4)
    }

    /// Maps a Protobuf Type to its default PackedPrimitiveType, if supported.
    pub fn from_proto_type(kind: Type) -> Option<Self> {
        let info = kind.primitive_info()?;
        match info.size {
            1 => {
                if kind == Type::Bool {
                    Some(Self::Bool)
                } else if info.is_signed {
                    Some(Self::I8)
                } else {
                    Some(Self::U8)
                }
            }
            2 => {
                if info.is_signed {
                    Some(Self::I16)
                } else {
                    Some(Self::U16)
                }
            }
            4 => {
                if kind == Type::Float {
                    Some(Self::F32)
                } else if info.is_signed {
                    Some(Self::I32)
                } else {
                    Some(Self::U32)
                }
            }
            8 => {
                if kind == Type::Double {
                    Some(Self::F64)
                } else if info.is_signed {
                    Some(Self::I64)
                } else {
                    Some(Self::U64)
                }
            }
            _ => None,
        }
    }
}

impl std::fmt::Display for PackedPrimitiveType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::U8 => "u8",
            Self::U16 => "u16",
            Self::U32 => "u32",
            Self::U64 => "u64",
            Self::I8 => "i8",
            Self::I16 => "i16",
            Self::I32 => "i32",
            Self::I64 => "i64",
            Self::F32 => "f32",
            Self::F64 => "f64",
            Self::Bool => "bool",
        };
        write!(f, "{}", name)
    }
}

/// The fully resolved packed type representation of a field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackedType {
    Primitive(PackedPrimitiveType),
    Array {
        elem: PackedPrimitiveType,
        len: usize,
    },
    Struct {
        name: String,
        size: usize,
    },
}

impl PackedType {
    /// Parses a PackedType from a string (e.g. "u32", "[u8; 16]").
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        if s.starts_with('[') && s.ends_with(']') {
            let inner = &s[1..s.len() - 1];
            let mut parts = inner.split(';');
            let elem_str = parts.next()?.trim();
            let len_str = parts.next()?.trim();
            if parts.next().is_some() {
                return None;
            }
            let elem = PackedPrimitiveType::parse(elem_str)?;
            let len = len_str.parse::<usize>().ok()?;
            Some(Self::Array { elem, len })
        } else {
            let prim = PackedPrimitiveType::parse(s)?;
            Some(Self::Primitive(prim))
        }
    }

    /// Returns the total size in bytes of this packed type.
    pub fn size(&self) -> usize {
        match self {
            Self::Primitive(prim) => prim.size(),
            Self::Array { elem, len } => elem.size() * len,
            Self::Struct { size, .. } => *size,
        }
    }

    /// Returns the alignment requirement in bytes of this packed type.
    pub fn alignment(&self) -> usize {
        match self {
            Self::Primitive(prim) => prim.alignment(),
            Self::Array { elem, .. } => elem.alignment(),
            Self::Struct { .. } => 4,
        }
    }

    /// Returns true if this type represents a floating point primitive.
    pub fn is_float(&self) -> bool {
        match self {
            Self::Primitive(prim) => prim.is_float(),
            _ => false,
        }
    }

    /// Returns true if this type represents a signed primitive.
    pub fn is_signed(&self) -> bool {
        match self {
            Self::Primitive(prim) => prim.is_signed(),
            _ => false,
        }
    }

    /// Maps a Protobuf Type to its default PackedType, if supported.
    pub fn from_proto_type(kind: Type) -> Option<Self> {
        PackedPrimitiveType::from_proto_type(kind).map(Self::Primitive)
    }
}

impl std::fmt::Display for PackedType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Primitive(prim) => write!(f, "{}", prim),
            Self::Array { elem, len } => write!(f, "[{}; {}]", elem, len),
            Self::Struct { name, .. } => write!(f, "{}", name),
        }
    }
}

/// Extension trait providing convenient access to TLV custom options on field descriptors.
pub trait FieldDescriptorProtoTlvExt {
    /// Returns the `offset` custom option value of this field, if present.
    fn offset(&self) -> Option<u32>;

    /// Returns the `type` custom option value of this field as a String, if present.
    fn type_option(&self) -> Option<String>;

    /// Returns the `bit_range` custom option value of this field as a String, if present.
    fn bit_range(&self) -> Option<String>;

    /// Returns true if the `extra_data` custom option is set to true on this field.
    fn extra_data(&self) -> bool;

    /// Resolves and validates the `FieldLayout` for this field.
    fn tlv_layout(
        &self,
        desc_set: &descriptor_rust_proto::FileDescriptorSet,
    ) -> Result<FieldLayout, TlvLayoutErrorKind>;
}

impl<'a> FieldDescriptorProtoTlvExt for FieldDescriptorProtoView<'a> {
    fn offset(&self) -> Option<u32> {
        let opt_bytes = self.options().serialize().ok()?;
        let reader = ProtoReader::new(&opt_bytes);
        match reader.find_field(OFFSET_OPTION_NUMBER) {
            Some(Record::Varint(val)) => Some(val as u32),
            _ => None,
        }
    }

    fn type_option(&self) -> Option<String> {
        let opt_bytes = self.options().serialize().ok()?;
        let reader = ProtoReader::new(&opt_bytes);
        match reader.find_field(TYPE_OPTION_NUMBER) {
            Some(Record::LengthDelimited(bytes)) => String::from_utf8(bytes.to_vec()).ok(),
            _ => None,
        }
    }

    fn bit_range(&self) -> Option<String> {
        let opt_bytes = self.options().serialize().ok()?;
        let reader = ProtoReader::new(&opt_bytes);
        match reader.find_field(BIT_RANGE_OPTION_NUMBER) {
            Some(Record::LengthDelimited(bytes)) => String::from_utf8(bytes.to_vec()).ok(),
            _ => None,
        }
    }

    fn extra_data(&self) -> bool {
        let Ok(opt_bytes) = self.options().serialize() else {
            return false;
        };
        let reader = ProtoReader::new(&opt_bytes);
        matches!(reader.find_field(EXTRA_DATA_OPTION_NUMBER), Some(Record::Varint(val)) if val != 0)
    }

    fn tlv_layout(
        &self,
        desc_set: &descriptor_rust_proto::FileDescriptorSet,
    ) -> Result<FieldLayout, TlvLayoutErrorKind> {
        let mut active_resolves = std::collections::HashSet::new();
        field_tlv_layout_rec(self, desc_set, &mut active_resolves)
    }
}

fn field_tlv_layout_rec(
    field: &FieldDescriptorProtoView<'_>,
    desc_set: &descriptor_rust_proto::FileDescriptorSet,
    active_resolves: &mut std::collections::HashSet<String>,
) -> Result<FieldLayout, TlvLayoutErrorKind> {
    use descriptor_rust_proto::field_descriptor_proto::Label;

    if field.extra_data() {
        if field.offset().is_some() {
            return Err(TlvLayoutErrorKind::ExtraDataWithOffset);
        }
        if field.label() == Label::Repeated {
            return Err(TlvLayoutErrorKind::RepeatedFieldCannotHaveExtraData);
        }
        if field.has_oneof_index() {
            return Err(TlvLayoutErrorKind::OneofFieldCannotHaveExtraData);
        }
        let kind = field.r#type();
        if !matches!(kind, Type::String | Type::Bytes) {
            return Err(TlvLayoutErrorKind::ExtraDataOnNonStringOrBytes { kind });
        }
        let Some(type_opt) = field.type_option() else {
            return Err(TlvLayoutErrorKind::ExtraDataMissingTypeOption);
        };
        if type_opt != "[u8]" {
            return Err(TlvLayoutErrorKind::ExtraDataUnsupportedType { value: type_opt });
        }
        return Ok(FieldLayout::ExtraData);
    }

    if field.label() == Label::Repeated && field.offset().is_some() {
        return Err(TlvLayoutErrorKind::RepeatedFieldCannotHaveOffset);
    }

    if field.has_oneof_index() && field.offset().is_some() {
        return Err(TlvLayoutErrorKind::OneofFieldCannotHaveOffset);
    }

    let kind = field.r#type();

    let explicit_type = field.type_option();
    let bit_range = field.bit_range();

    if bit_range.is_some() && field.offset().is_some() {
        return Err(TlvLayoutErrorKind::BitRangeOnNonPackableType { kind });
    }

    let offset = match field.offset() {
        Some(o) => o as usize,
        None => {
            if kind.primitive_info().is_some() {
                return Err(TlvLayoutErrorKind::MissingOffset { kind });
            }

            if !matches!(kind, Type::Message | Type::Group) {
                return Err(TlvLayoutErrorKind::UnsupportedFieldType { kind });
            }

            // There is no offset, so this must be a TLV field.

            let type_name_raw = field.type_name().to_str().unwrap_or("");
            let type_name = type_name_raw.strip_prefix('.').unwrap_or(type_name_raw);

            let child_desc = find_message_descriptor(desc_set, type_name).ok_or_else(|| {
                TlvLayoutErrorKind::NestedMessageNotFound {
                    type_name: type_name.to_string(),
                }
            })?;

            if child_desc.bit_packed().map_err(|e| e.kind)?.is_some() {
                return Err(TlvLayoutErrorKind::BitPackedCannotBeTlv {
                    type_name: type_name.to_string(),
                });
            }

            let tag =
                child_desc
                    .tlv_fourcc()
                    .ok_or_else(|| TlvLayoutErrorKind::MissingTlvFourcc {
                        type_name: type_name.to_string(),
                    })?;

            return Ok(FieldLayout::Tlv { kind, tag });
        }
    };

    // Packable primitive types -> Valid Fixed layout!
    if kind.primitive_info().is_some() {
        let packed_type = if let Some(type_str) = explicit_type {
            let Some(parsed_type) = PackedType::parse(&type_str) else {
                return Err(TlvLayoutErrorKind::InvalidTypeOption { value: type_str });
            };
            // Ensure it is a primitive type (not an array)
            if matches!(parsed_type, PackedType::Array { .. }) {
                return Err(TlvLayoutErrorKind::InvalidTypeOption { value: type_str });
            }

            // Validate signedness matches!
            let info = kind.primitive_info().unwrap();
            if info.is_signed != parsed_type.is_signed() {
                return Err(TlvLayoutErrorKind::SignednessMismatch {
                    proto_type: kind,
                    value: type_str,
                });
            }

            // Validate float/integer matches!
            if info.is_float != parsed_type.is_float() {
                return Err(TlvLayoutErrorKind::FloatIntegerMismatch {
                    proto_type: kind,
                    value: type_str,
                });
            }

            parsed_type
        } else if kind == descriptor_rust_proto::field_descriptor_proto::Type::Enum {
            let type_name_raw = field.type_name().to_str().unwrap_or("");
            let type_name = type_name_raw.strip_prefix('.').unwrap_or(type_name_raw);
            let raw_type_str = find_enum_descriptor(desc_set, type_name)
                .and_then(|e| e.raw_type())
                .unwrap_or_else(|| "i32".to_string());

            let Some(parsed_type) = PackedType::parse(&raw_type_str) else {
                return Err(TlvLayoutErrorKind::InvalidTypeOption {
                    value: raw_type_str,
                });
            };
            parsed_type
        } else {
            PackedType::from_proto_type(kind)
                .ok_or(TlvLayoutErrorKind::UnsupportedFieldType { kind })?
        };

        if matches!(
            packed_type,
            PackedType::Primitive(PackedPrimitiveType::Bool)
        ) {
            return Err(TlvLayoutErrorKind::StandaloneBoolNotSupported);
        }

        let align = packed_type.alignment();

        if offset % align != 0 {
            return Err(TlvLayoutErrorKind::UnalignedOffset {
                offset,
                size: align,
            });
        }

        return Ok(FieldLayout::Fixed {
            offset,
            packed_type,
        });
    }

    match kind {
        Type::String | Type::Bytes => {
            // String/bytes are allowed to be packed as fixed arrays
            if let Some(type_str) = explicit_type {
                let Some(parsed_type) = PackedType::parse(&type_str) else {
                    return Err(TlvLayoutErrorKind::InvalidTypeOption { value: type_str });
                };
                let size = parsed_type.size();
                if size == 0 {
                    return Err(TlvLayoutErrorKind::ZeroSizeStringOrBytes);
                }
                // String/bytes must be packed as an array type in the fixed struct
                if !matches!(parsed_type, PackedType::Array { .. }) {
                    return Err(TlvLayoutErrorKind::InvalidTypeOption { value: type_str });
                }

                // Validate it is not a boolean array
                if matches!(
                    parsed_type,
                    PackedType::Array {
                        elem: PackedPrimitiveType::Bool,
                        ..
                    }
                ) {
                    return Err(TlvLayoutErrorKind::StandaloneBoolNotSupported);
                }
                let align = parsed_type.alignment();
                if offset % align != 0 {
                    return Err(TlvLayoutErrorKind::UnalignedOffset {
                        offset,
                        size: align,
                    });
                }
                Ok(FieldLayout::Fixed {
                    offset,
                    packed_type: parsed_type,
                })
            } else {
                Err(TlvLayoutErrorKind::MissingTypeOption { kind, offset })
            }
        }

        Type::Message | Type::Group => {
            // Nested messages/groups are allowed to be packed as fixed
            // data if they have no sub TLVs
            let type_name_raw = field.type_name().to_str().unwrap_or("");
            let type_name = type_name_raw.strip_prefix('.').unwrap_or(type_name_raw);

            let child_desc = find_message_descriptor(desc_set, type_name).ok_or_else(|| {
                TlvLayoutErrorKind::NestedMessageNotFound {
                    type_name: type_name.to_string(),
                }
            })?;

            let child_layout = tlv_layout_rec(&child_desc, type_name, desc_set, active_resolves)
                .map_err(|e| e.kind)?;

            match child_layout {
                TlvLayout::BitPacked { backing, .. } => {
                    let size = backing.size();

                    if size > 0 && offset % size != 0 {
                        return Err(TlvLayoutErrorKind::UnalignedOffset { offset, size });
                    }

                    let rust_type = get_rust_struct_name(type_name, desc_set);
                    Ok(FieldLayout::Fixed {
                        offset,
                        packed_type: PackedType::Struct {
                            name: rust_type,
                            size,
                        },
                    })
                }
                TlvLayout::Standard {
                    fields,
                    fixed_struct_size,
                } => {
                    let has_dynamic_tlvs = fields
                        .values()
                        .any(|f| matches!(f, FieldLayout::Tlv { .. }));
                    if has_dynamic_tlvs {
                        return Err(TlvLayoutErrorKind::NestedMessageNotPackable {
                            type_name: type_name.to_string(),
                        });
                    }

                    let max_align = fields
                        .values()
                        .map(|f| match f {
                            FieldLayout::Fixed { packed_type, .. } => packed_type.alignment(),
                            _ => 1,
                        })
                        .max()
                        .unwrap_or(1);

                    if max_align > 0 && offset % max_align != 0 {
                        return Err(TlvLayoutErrorKind::UnalignedOffset {
                            offset,
                            size: max_align,
                        });
                    }

                    let rust_type = get_rust_struct_name(type_name, desc_set);
                    Ok(FieldLayout::Fixed {
                        offset,
                        packed_type: PackedType::Struct {
                            name: rust_type,
                            size: fixed_struct_size,
                        },
                    })
                }
            }
        }

        _ => Err(TlvLayoutErrorKind::UnsupportedFieldType { kind }),
    }
}

fn normalize_name(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_alphanumeric())
        .collect::<String>()
        .to_lowercase()
}

fn extract_simple_name(type_name: &str) -> &str {
    if let Some(pos) = type_name.rfind("::") {
        &type_name[pos + 2..]
    } else if let Some(pos) = type_name.rfind('.') {
        &type_name[pos + 1..]
    } else {
        type_name
    }
}

pub fn get_rust_struct_name(
    full_type_name: &str,
    desc_set: &descriptor_rust_proto::FileDescriptorSet,
) -> String {
    let mut best_package = "";
    for file in desc_set.file() {
        let pkg = file.package().to_str().unwrap();
        let pkg_prefix = if pkg.is_empty() {
            "".to_string()
        } else {
            format!("{}.", pkg)
        };
        if full_type_name.starts_with(&pkg_prefix) {
            if pkg.len() > best_package.len() {
                best_package = pkg;
            }
        }
    }

    let relative_name = if best_package.is_empty() {
        full_type_name
    } else {
        full_type_name
            .strip_prefix(&format!("{}.", best_package))
            .unwrap_or(full_type_name)
    };

    relative_name.replace('.', "_")
}

pub fn find_message_descriptor<'a>(
    desc_set: &'a descriptor_rust_proto::FileDescriptorSet,
    message_name: &str,
) -> Option<descriptor_rust_proto::DescriptorProtoView<'a>> {
    // 1. Collect all message candidates whose simple name matches the target name.
    let mut candidates = Vec::new();
    let simple_target = extract_simple_name(message_name);

    for file in desc_set.file() {
        for message in file.message_type() {
            collect_candidates(message, "", simple_target, &mut candidates);
        }
    }

    if candidates.is_empty() {
        None
    } else if candidates.len() == 1 {
        // Happy path: no name collision! Highly efficient and dead simple.
        Some(candidates[0].0)
    } else {
        // Collision path: disambiguate using suffix matching on the full Rust type path.
        disambiguate_candidate(candidates, message_name)
    }
}

pub fn find_enum_descriptor<'a>(
    desc_set: &'a descriptor_rust_proto::FileDescriptorSet,
    enum_name: &str,
) -> Option<descriptor_rust_proto::EnumDescriptorProtoView<'a>> {
    let target = format!(".{}", enum_name.strip_prefix('.').unwrap_or(enum_name));

    for file in desc_set.file() {
        let package = file.package().to_str().unwrap_or("");
        let prefix = if package.is_empty() {
            ".".to_string()
        } else {
            format!(".{}.", package)
        };
        for en in file.enum_type() {
            if format!("{}{}", prefix, en.name().to_str().unwrap_or("")) == target {
                return Some(en);
            }
        }
        for msg in file.message_type() {
            if let Some(found) = find_enum_nested(&prefix, msg, &target) {
                return Some(found);
            }
        }
    }
    None
}

fn find_enum_nested<'a>(
    parent_prefix: &str,
    msg: DescriptorProtoView<'a>,
    target: &str,
) -> Option<descriptor_rust_proto::EnumDescriptorProtoView<'a>> {
    let msg_name = msg.name().to_str().unwrap_or("");
    let prefix = format!("{}{}.", parent_prefix, msg_name);

    for en in msg.enum_type() {
        if format!("{}{}", prefix, en.name().to_str().unwrap_or("")) == target {
            return Some(en);
        }
    }
    for nested in msg.nested_type() {
        if let Some(found) = find_enum_nested(&prefix, nested, target) {
            return Some(found);
        }
    }
    None
}

fn collect_candidates<'a>(
    msg: DescriptorProtoView<'a>,
    parent_path: &str,
    simple_target: &str,
    out: &mut Vec<(DescriptorProtoView<'a>, String)>,
) {
    let name = msg.name().to_str().unwrap_or("");
    let current_path = if parent_path.is_empty() {
        name.to_string()
    } else {
        format!("{}.{}", parent_path, name)
    };

    if name == simple_target {
        out.push((msg, current_path.clone()));
    }

    for nested in msg.nested_type() {
        collect_candidates(nested, &current_path, simple_target, out);
    }
}

fn disambiguate_candidate<'a>(
    candidates: Vec<(DescriptorProtoView<'a>, String)>,
    target_name: &str,
) -> Option<DescriptorProtoView<'a>> {
    let norm_target = normalize_name(target_name);
    let mut best_match: Option<(DescriptorProtoView<'a>, usize)> = None;

    for (desc, path) in candidates {
        let norm_path = normalize_name(&path);
        if norm_target.ends_with(&norm_path) {
            let match_len = norm_path.len();
            let should_update = match best_match {
                Some((_, best_len)) => match_len > best_len,
                None => true,
            };
            if should_update {
                best_match = Some((desc, match_len));
            }
        }
    }

    best_match.map(|(desc, _)| desc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use protobuf::Parse;

    fn get_bad_desc_set() -> descriptor_rust_proto::FileDescriptorSet {
        const BYTES: &[u8] = include_bytes!(env!("BAD_PROTO_DESCRIPTOR_SET"));
        descriptor_rust_proto::FileDescriptorSet::parse(BYTES).unwrap()
    }

    fn find_msg_descriptor<'a>(
        desc_set: &'a descriptor_rust_proto::FileDescriptorSet,
        name: &str,
    ) -> descriptor_rust_proto::DescriptorProtoView<'a> {
        for file in desc_set.file() {
            for message in file.message_type() {
                if message.name().to_str().unwrap_or("") == name {
                    return message;
                }
            }
        }
        panic!("Message not found: {}", name);
    }

    #[test]
    fn test_unaligned_offset() {
        let desc_set = get_bad_desc_set();
        let msg = find_msg_descriptor(&desc_set, "MessageUnalignedOffset");
        let err = msg.tlv_layout(&desc_set).unwrap_err();

        // Assert un-prefixed error message
        assert_eq!(
            err.to_string(),
            "Invalid TLV layout on field 'val' of message 'MessageUnalignedOffset': offset of 3 is not naturally aligned to its size of 4 bytes (offset must be a multiple of size)."
        );
    }

    #[test]
    fn test_overlapping_fields() {
        let desc_set = get_bad_desc_set();
        let msg = find_msg_descriptor(&desc_set, "MessageOverlappingFields");
        let err = msg.tlv_layout(&desc_set).unwrap_err();

        assert_eq!(
            err.to_string(),
            "Invalid TLV layout in message 'MessageOverlappingFields': field 'val1' (bytes 0..8) overlaps with field 'val2' (bytes 4..8) in the fixed struct."
        );
    }

    #[test]
    fn test_missing_offset() {
        let desc_set = get_bad_desc_set();
        let msg = find_msg_descriptor(&desc_set, "MessageMissingOffset");
        let err = msg.tlv_layout(&desc_set).unwrap_err();

        assert_eq!(
            err.to_string(),
            "Invalid TLV layout on field 'val' of message 'MessageMissingOffset': primitive field of type 'Type::Uint32' is missing a custom 'offset' option. All primitive fields in a TLV-serializable message must be packed in the fixed struct."
        );
    }

    #[test]
    fn test_missing_type_option() {
        let desc_set = get_bad_desc_set();
        let msg = find_msg_descriptor(&desc_set, "MessageMissingTypeOption");
        let err = msg.tlv_layout(&desc_set).unwrap_err();

        assert_eq!(
            err.to_string(),
            "Invalid TLV layout on field 'name' of message 'MessageMissingTypeOption': field of type 'Type::String' has a custom offset (0) but is missing an explicit 'type' option. Inline strings or byte arrays in the fixed struct must specify an explicit type."
        );
    }

    #[test]
    fn test_invalid_type_option() {
        let desc_set = get_bad_desc_set();
        let msg = find_msg_descriptor(&desc_set, "MessageInvalidTypeOption");
        let err = msg.tlv_layout(&desc_set).unwrap_err();

        assert_eq!(
            err.to_string(),
            "Invalid TLV layout on field 'val' of message 'MessageInvalidTypeOption': explicit type option must be a valid Rust type (got 'u24')."
        );
    }

    #[test]
    fn test_unsupported_field_type() {
        let desc_set = get_bad_desc_set();
        let msg = find_msg_descriptor(&desc_set, "MessageUnsupportedFieldType");
        let err = msg.tlv_layout(&desc_set).unwrap_err();

        assert_eq!(
            err.to_string(),
            "Invalid TLV layout on field 'name' of message 'MessageUnsupportedFieldType': Protobuf type 'Type::String' is not supported for TLV layout (only packable primitives, inline strings/bytes, and nested sub-messages are supported)."
        );
    }

    #[test]
    fn test_standalone_bool() {
        let desc_set = get_bad_desc_set();
        let msg = find_msg_descriptor(&desc_set, "MessageStandaloneBool");
        let err = msg.tlv_layout(&desc_set).unwrap_err();

        assert_eq!(
            err.to_string(),
            "Invalid TLV layout on field 'val' of message 'MessageStandaloneBool': standalone boolean fields are not supported because they cannot be safely decoded via zero-copy. Use a custom 'type' option to map the field to an integer type (e.g. `[(openprot.tlv.type) = \"u8\"]`), or place the field inside a bit-packed message (using `option (openprot.tlv.bit_packed) = ...;`)."
        );
    }

    #[test]
    fn test_signedness_mismatch_signed_to_unsigned() {
        let desc_set = get_bad_desc_set();
        let msg = find_msg_descriptor(&desc_set, "MessageSignednessMismatchSignedToUnsigned");
        let err = msg.tlv_layout(&desc_set).unwrap_err();

        assert_eq!(
            err.to_string(),
            "Invalid TLV layout on field 'val' of message 'MessageSignednessMismatchSignedToUnsigned': signedness mismatch: Protobuf field type 'Type::Sint32' (signed) does not match the signedness of the custom TLV type 'u8' (unsigned). Signed Protobuf fields must be mapped to signed Rust types (e.g. i8, i16, i32, i64)."
        );
    }

    #[test]
    fn test_signedness_mismatch_unsigned_to_signed() {
        let desc_set = get_bad_desc_set();
        let msg = find_msg_descriptor(&desc_set, "MessageSignednessMismatchUnsignedToSigned");
        let err = msg.tlv_layout(&desc_set).unwrap_err();

        assert_eq!(
            err.to_string(),
            "Invalid TLV layout on field 'val' of message 'MessageSignednessMismatchUnsignedToSigned': signedness mismatch: Protobuf field type 'Type::Uint32' (unsigned) does not match the signedness of the custom TLV type 'i8' (signed). Unsigned Protobuf fields must be mapped to unsigned Rust types (e.g. u8, u16, u32, u64)."
        );
    }

    #[test]
    fn test_float_to_integer_mismatch() {
        let desc_set = get_bad_desc_set();
        let msg = find_msg_descriptor(&desc_set, "MessageFloatToIntegerMismatch");
        let err = msg.tlv_layout(&desc_set).unwrap_err();

        assert_eq!(
            err.to_string(),
            "Invalid TLV layout on field 'val' of message 'MessageFloatToIntegerMismatch': type mismatch: Protobuf field type 'Type::Float' (floating-point) does not match the custom TLV type 'i32' (integer). Floating-point Protobuf fields must be mapped to floating-point Rust types (f32, f64)."
        );
    }

    #[test]
    fn test_integer_to_float_mismatch() {
        let desc_set = get_bad_desc_set();
        let msg = find_msg_descriptor(&desc_set, "MessageIntegerToFloatMismatch");
        let err = msg.tlv_layout(&desc_set).unwrap_err();

        assert_eq!(
            err.to_string(),
            "Invalid TLV layout on field 'val' of message 'MessageIntegerToFloatMismatch': type mismatch: Protobuf field type 'Type::Int32' (integer) does not match the custom TLV type 'f32' (floating-point). Integer Protobuf fields must be mapped to integer Rust types (e.g. i8, u8, i16, u16, i32, u32, i64, u64)."
        );
    }

    #[test]
    fn test_boolean_array() {
        let desc_set = get_bad_desc_set();
        let msg = find_msg_descriptor(&desc_set, "MessageBooleanArray");
        let err = msg.tlv_layout(&desc_set).unwrap_err();

        assert_eq!(
            err.to_string(),
            "Invalid TLV layout on field 'val' of message 'MessageBooleanArray': standalone boolean fields are not supported because they cannot be safely decoded via zero-copy. Use a custom 'type' option to map the field to an integer type (e.g. `[(openprot.tlv.type) = \"u8\"]`), or place the field inside a bit-packed message (using `option (openprot.tlv.bit_packed) = ...;`)."
        );
    }

    #[test]
    fn test_repeated_field_with_offset() {
        let desc_set = get_bad_desc_set();
        let msg = find_msg_descriptor(&desc_set, "MessageRepeatedFieldWithOffset");
        let err = msg.tlv_layout(&desc_set).unwrap_err();

        assert_eq!(
            err.to_string(),
            "Invalid TLV layout on field 'values' of message 'MessageRepeatedFieldWithOffset': repeated fields are not allowed to specify a custom 'offset' option because their size is dynamic. They must be serialized as dynamic sub-TLVs (omit the 'offset' option)."
        );
    }

    #[test]
    fn test_oneof_field_with_offset() {
        let desc_set = get_bad_desc_set();
        let msg = find_msg_descriptor(&desc_set, "MessageOneofFieldWithOffset");
        let err = msg.tlv_layout(&desc_set).unwrap_err();

        assert_eq!(
            err.to_string(),
            "Invalid TLV layout on field 'val' of message 'MessageOneofFieldWithOffset': fields inside a 'oneof' are not allowed to specify a custom 'offset' option because they are mutually exclusive. They must be serialized as dynamic sub-TLVs (omit the 'offset' option)."
        );
    }

    #[test]
    fn test_missing_bit_range() {
        let desc_set = get_bad_desc_set();
        let msg = find_msg_descriptor(&desc_set, "MessageMissingBitRange");
        let err = msg.tlv_layout(&desc_set).unwrap_err();

        assert_eq!(
            err.to_string(),
            "Invalid TLV layout on field 'val2' of message 'MessageMissingBitRange': field in a bit-packed message is missing the required 'bit_range' option."
        );
    }

    #[test]
    fn test_offset_or_size_in_bit_packed() {
        let desc_set = get_bad_desc_set();
        let msg = find_msg_descriptor(&desc_set, "MessageOffsetOrSizeInBitPacked");
        let err = msg.tlv_layout(&desc_set).unwrap_err();

        assert_eq!(
            err.to_string(),
            "Invalid TLV layout on field 'val' of message 'MessageOffsetOrSizeInBitPacked': field in a bit-packed message is not allowed to specify 'offset' or 'type' options; use the 'bit_range' option to specify its position."
        );
    }

    #[test]
    fn test_bit_range_on_non_packable_type() {
        let desc_set = get_bad_desc_set();
        let msg = find_msg_descriptor(&desc_set, "MessageBitRangeOnNonPackableType");
        let err = msg.tlv_layout(&desc_set).unwrap_err();

        assert_eq!(
            err.to_string(),
            "Invalid TLV layout on field 'name' of message 'MessageBitRangeOnNonPackableType': bit_range option is only supported on packable primitive integer, enum, or boolean types (got 'Type::String')."
        );
    }

    #[test]
    fn test_invalid_bit_range_format() {
        let desc_set = get_bad_desc_set();
        let msg = find_msg_descriptor(&desc_set, "MessageInvalidBitRangeFormat");
        let err = msg.tlv_layout(&desc_set).unwrap_err();

        assert_eq!(
            err.to_string(),
            "Invalid TLV layout on field 'val' of message 'MessageInvalidBitRangeFormat': invalid bit_range format: '7-0' (must be Verilog notation like 'high:low')."
        );
    }

    #[test]
    fn test_invalid_bit_range_order() {
        let desc_set = get_bad_desc_set();
        let msg = find_msg_descriptor(&desc_set, "MessageInvalidBitRangeOrder");
        let err = msg.tlv_layout(&desc_set).unwrap_err();

        assert_eq!(
            err.to_string(),
            "Invalid TLV layout on field 'val' of message 'MessageInvalidBitRangeOrder': invalid bit_range order '3:4': high bit must be greater than or equal to low bit."
        );
    }

    #[test]
    fn test_overlapping_bits() {
        let desc_set = get_bad_desc_set();
        let msg = find_msg_descriptor(&desc_set, "MessageOverlappingBits");
        let err = msg.tlv_layout(&desc_set).unwrap_err();

        assert_eq!(
            err.to_string(),
            "Invalid TLV layout in message 'MessageOverlappingBits': field 'val1' (bits 15:0) overlaps with field 'val2' (bits 16:15) in the bit-packed register."
        );
    }

    #[test]
    fn test_nested_message_not_packable() {
        let desc_set = get_bad_desc_set();
        let msg = find_msg_descriptor(&desc_set, "MessageNestedMessageNotPackable");
        let err = msg.tlv_layout(&desc_set).unwrap_err();

        assert_eq!(
            err.to_string(),
            "Invalid TLV layout on field 'nested' of message 'MessageNestedMessageNotPackable': nested message field has a custom offset but its type 'openprot.tlv.test.bad.NestedMsgWithTlv' is not packable inline (it must be bit-packed or a standard struct with no dynamic sub-TLVs)."
        );
    }

    #[test]
    fn test_overlap_fixed_sub_message() {
        let desc_set = get_bad_desc_set();
        let msg = find_msg_descriptor(&desc_set, "MessageOverlapFixedSubMessage");
        let err = msg.tlv_layout(&desc_set).unwrap_err();

        assert_eq!(
            err.to_string(),
            "Invalid TLV layout in message 'MessageOverlapFixedSubMessage': field 'sub' (bytes 0..16) overlaps with field 'val' (bytes 12..16) in the fixed struct."
        );
    }

    #[test]
    fn test_overlap_bit_packed() {
        let desc_set = get_bad_desc_set();
        let msg = find_msg_descriptor(&desc_set, "MessageOverlapBitPacked");
        let err = msg.tlv_layout(&desc_set).unwrap_err();

        assert_eq!(
            err.to_string(),
            "Invalid TLV layout in message 'MessageOverlapBitPacked': field 'reg' (bytes 0..4) overlaps with field 'val' (bytes 0..4) in the fixed struct."
        );
    }

    #[test]
    fn test_bit_packed_width_exceeded() {
        let desc_set = get_bad_desc_set();
        let msg = find_msg_descriptor(&desc_set, "MessageBitPackedWidthExceeded");
        let err = msg.tlv_layout(&desc_set).unwrap_err();

        assert_eq!(
            err.to_string(),
            "Invalid TLV layout on field 'val2' of message 'MessageBitPackedWidthExceeded': bit_range high bit 8 is out of bounds for the backing register width of 8 bits."
        );
    }

    #[test]
    fn test_invalid_bit_packed_type() {
        let desc_set = get_bad_desc_set();
        let msg = find_msg_descriptor(&desc_set, "MessageInvalidBitPackedType");
        let err = msg.tlv_layout(&desc_set).unwrap_err();

        assert_eq!(
            err.to_string(),
            "Invalid TLV layout in message 'MessageInvalidBitPackedType': invalid value for 'bit_packed' option: 'u64' (must be 'u8', 'u16', or 'u32')."
        );
    }

    #[test]
    fn test_bit_packed_as_tlv() {
        let desc_set = get_bad_desc_set();
        let msg = find_msg_descriptor(&desc_set, "MessageBitPackedAsTlv");
        let err = msg.tlv_layout(&desc_set).unwrap_err();

        assert_eq!(
            err.to_string(),
            "Invalid TLV layout on field 'reg' of message 'MessageBitPackedAsTlv': bit-packed message of type 'openprot.tlv.test.bad.LargePackedRegister' cannot be serialized as a dynamic sub-TLV; it must be packed inline inside the fixed struct using a custom 'offset' option."
        );
    }

    #[test]
    fn test_bit_packed_with_fourcc() {
        let desc_set = get_bad_desc_set();
        let msg = find_msg_descriptor(&desc_set, "MessageBitPackedWithFourcc");
        let err = msg.tlv_layout(&desc_set).unwrap_err();

        assert_eq!(
            err.to_string(),
            "Invalid TLV layout in message 'MessageBitPackedWithFourcc': message is bit-packed and cannot specify a 'tlv_fourcc' option; bit-packed messages are raw registers and cannot be serialized as TLV blocks."
        );
    }

    #[test]
    fn test_unaligned_bit_packed() {
        let desc_set = get_bad_desc_set();
        let msg = find_msg_descriptor(&desc_set, "MessageUnalignedBitPacked");
        let err = msg.tlv_layout(&desc_set).unwrap_err();

        assert_eq!(
            err.to_string(),
            "Invalid TLV layout on field 'reg' of message 'MessageUnalignedBitPacked': offset of 2 is not naturally aligned to its size of 4 bytes (offset must be a multiple of size)."
        );
    }

    #[test]
    fn test_unaligned_nested_struct() {
        let desc_set = get_bad_desc_set();
        let msg = find_msg_descriptor(&desc_set, "MessageUnalignedNestedStruct");
        let err = msg.tlv_layout(&desc_set).unwrap_err();

        assert_eq!(
            err.to_string(),
            "Invalid TLV layout on field 'sub' of message 'MessageUnalignedNestedStruct': offset of 2 is not naturally aligned to its size of 4 bytes (offset must be a multiple of size)."
        );
    }

    #[test]
    fn test_zero_size_inline_string() {
        let desc_set = get_bad_desc_set();
        let msg = find_msg_descriptor(&desc_set, "MessageZeroSizeInlineString");
        let err = msg.tlv_layout(&desc_set).unwrap_err();

        assert_eq!(
            err.to_string(),
            "Invalid TLV layout on field 'name' of message 'MessageZeroSizeInlineString': explicit size option for inline string or bytes fields must be greater than 0."
        );
    }

    #[test]
    fn test_nested_message_in_bit_packed() {
        let desc_set = get_bad_desc_set();
        let msg = find_msg_descriptor(&desc_set, "MessageNestedMessageInBitPacked");
        let err = msg.tlv_layout(&desc_set).unwrap_err();

        assert_eq!(
            err.to_string(),
            "Invalid TLV layout on field 'nested' of message 'MessageNestedMessageInBitPacked': bit_range option is only supported on packable primitive integer, enum, or boolean types (got 'Type::Message')."
        );
    }

    #[test]
    fn test_float_in_bit_packed() {
        let desc_set = get_bad_desc_set();
        let msg = find_msg_descriptor(&desc_set, "MessageFloatInBitPacked");
        let err = msg.tlv_layout(&desc_set).unwrap_err();

        assert_eq!(
            err.to_string(),
            "Invalid TLV layout on field 'val' of message 'MessageFloatInBitPacked': bit_range option is only supported on packable primitive integer, enum, or boolean types (got 'Type::Float')."
        );
    }

    #[test]
    fn test_type_in_bit_packed() {
        let desc_set = get_bad_desc_set();
        let msg = find_msg_descriptor(&desc_set, "MessageTypeInBitPacked");
        let err = msg.tlv_layout(&desc_set).unwrap_err();

        assert_eq!(
            err.to_string(),
            "Invalid TLV layout on field 'val' of message 'MessageTypeInBitPacked': field in a bit-packed message is not allowed to specify 'offset' or 'type' options; use the 'bit_range' option to specify its position."
        );
    }
    #[test]
    fn test_name_collision_resolution() {
        // Reconstruct FileDescriptorSet from the edge_cases DescriptorInfo
        let info = &edge_cases_rust_proto::__unstable::CONTRIB_TLV_TEST_EDGE_CASES_DESCRIPTOR_INFO;

        let desc_set = collect_descriptor_set(info).expect("Failed to collect descriptor set");

        // 1. Resolve using the fully-qualified name of the nested message
        let nested_desc = find_message_descriptor(
            &desc_set,
            "openprot.tlv.test.edge_cases.MessageCollisionContainer.PackedRegister",
        )
        .expect("Failed to find nested MessageCollisionContainer.PackedRegister");

        // The nested message has only a single field: 'val'
        let mut nested_field_names = Vec::new();
        for field in nested_desc.field() {
            nested_field_names.push(field.name().to_str().unwrap().to_string());
        }
        assert_eq!(nested_field_names, vec!["val"]);

        // 2. Resolve using the fully-qualified name of the top-level message
        let top_desc =
            find_message_descriptor(&desc_set, "openprot.tlv.test.edge_cases.PackedRegister")
                .expect("Failed to find top-level PackedRegister");

        // The top-level message has fields: 'enabled', 'mode', 'status', 'val'
        let mut top_field_names = Vec::new();
        for field in top_desc.field() {
            top_field_names.push(field.name().to_str().unwrap().to_string());
        }
        assert_eq!(top_field_names, vec!["enabled", "mode", "status", "val"]);
    }

    #[test]
    fn test_unaligned_inline_string() {
        let desc_set = get_bad_desc_set();
        let msg = find_msg_descriptor(&desc_set, "MessageUnalignedInlineString");
        let err = msg.tlv_layout(&desc_set).unwrap_err();

        assert_eq!(
            err.to_string(),
            "Invalid TLV layout on field 'name' of message 'MessageUnalignedInlineString': offset of 3 is not naturally aligned to its size of 4 bytes (offset must be a multiple of size)."
        );
    }

    #[test]
    fn test_unaligned_inline_bytes() {
        let desc_set = get_bad_desc_set();
        let msg = find_msg_descriptor(&desc_set, "MessageUnalignedInlineBytes");
        let err = msg.tlv_layout(&desc_set).unwrap_err();

        assert_eq!(
            err.to_string(),
            "Invalid TLV layout on field 'data' of message 'MessageUnalignedInlineBytes': offset of 3 is not naturally aligned to its size of 4 bytes (offset must be a multiple of size)."
        );
    }

    #[test]
    fn test_error_string_nested_message_not_found() {
        let err = TlvLayoutError {
            message_name: "MyMessage".to_string(),
            field_name: Some("my_field".to_string()),
            kind: TlvLayoutErrorKind::NestedMessageNotFound {
                type_name: "NonExistentMessage".to_string(),
            },
        };
        assert_eq!(
            err.to_string(),
            "Invalid TLV layout on field 'my_field' of message 'MyMessage': nested message type descriptor for 'NonExistentMessage' was not found in the descriptor set."
        );
    }

    #[test]
    fn test_missing_tlv_fourcc_sub() {
        let desc_set = get_bad_desc_set();
        let msg = find_msg_descriptor(&desc_set, "MessageWithMissingFourccSub");
        let err = msg.tlv_layout(&desc_set).unwrap_err();

        assert_eq!(
            err.to_string(),
            "Invalid TLV layout on field 'sub' of message 'MessageWithMissingFourccSub': nested message 'openprot.tlv.test.bad.MissingFourccSub' acts as a dynamic sub-TLV but is missing a 'tlv_fourcc' option; sub-TLVs must have a unique 4-character tag."
        );
    }

    #[test]
    fn test_duplicate_tlv_tag() {
        let desc_set = get_bad_desc_set();
        let msg = find_msg_descriptor(&desc_set, "MessageWithDuplicateTlvTags");
        let err = msg.tlv_layout(&desc_set).unwrap_err();

        assert_eq!(
            err.to_string(),
            "Invalid TLV layout in message 'MessageWithDuplicateTlvTags': sub-TLV fields 'gpu' and 'npu' share the same tlv_fourcc tag 'ACCL'; all sub-TLV fields within a message must have unique tags to prevent decoding ambiguity."
        );
    }

    #[test]
    fn test_circular_dependency() {
        let desc_set = get_bad_desc_set();
        let msg = find_msg_descriptor(&desc_set, "CircularA");
        let err = msg
            .tlv_layout_with_name("openprot.tlv.test.bad.CircularA", &desc_set)
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "Invalid TLV layout on field 'b' of message 'CircularA': circular dependency detected: message 'openprot.tlv.test.bad.CircularA' directly or indirectly contains itself inline, which requires infinite struct size."
        );
    }

    #[test]
    fn test_multiple_extra_data_fields() {
        let desc_set = get_bad_desc_set();
        let msg = find_msg_descriptor(&desc_set, "MessageMultipleExtraDataFields");
        let err = msg.tlv_layout(&desc_set).unwrap_err();

        assert_eq!(
            err.to_string(),
            "Invalid TLV layout in message 'MessageMultipleExtraDataFields': message cannot have more than one field with 'extra_data' option."
        );
    }

    #[test]
    fn test_extra_data_with_sub_tlvs() {
        let desc_set = get_bad_desc_set();
        let msg = find_msg_descriptor(&desc_set, "MessageExtraDataWithSubTlvs");
        let err = msg.tlv_layout(&desc_set).unwrap_err();

        assert_eq!(
            err.to_string(),
            "Invalid TLV layout in message 'MessageExtraDataWithSubTlvs': message with an 'extra_data' field cannot also contain dynamic sub-TLVs."
        );
    }

    #[test]
    fn test_extra_data_on_invalid_type() {
        let desc_set = get_bad_desc_set();
        let msg = find_msg_descriptor(&desc_set, "MessageExtraDataOnInvalidType");
        let err = msg.tlv_layout(&desc_set).unwrap_err();

        assert_eq!(
            err.to_string(),
            "Invalid TLV layout on field 'val' of message 'MessageExtraDataOnInvalidType': 'extra_data' option is only supported on 'string' or 'bytes' fields (got 'Type::Uint32')."
        );
    }

    #[test]
    fn test_extra_data_with_offset() {
        let desc_set = get_bad_desc_set();
        let msg = find_msg_descriptor(&desc_set, "MessageExtraDataWithOffset");
        let err = msg.tlv_layout(&desc_set).unwrap_err();

        assert_eq!(
            err.to_string(),
            "Invalid TLV layout on field 'ext' of message 'MessageExtraDataWithOffset': field with 'extra_data' option cannot specify a custom 'offset' option."
        );
    }

    #[test]
    fn test_repeated_extra_data() {
        let desc_set = get_bad_desc_set();
        let msg = find_msg_descriptor(&desc_set, "MessageRepeatedExtraData");
        let err = msg.tlv_layout(&desc_set).unwrap_err();

        assert_eq!(
            err.to_string(),
            "Invalid TLV layout on field 'chunks' of message 'MessageRepeatedExtraData': field with 'extra_data' option cannot be 'repeated'."
        );
    }

    #[test]
    fn test_oneof_extra_data() {
        let desc_set = get_bad_desc_set();
        let msg = find_msg_descriptor(&desc_set, "MessageOneofExtraData");
        let err = msg.tlv_layout(&desc_set).unwrap_err();

        assert_eq!(
            err.to_string(),
            "Invalid TLV layout on field 'ext' of message 'MessageOneofExtraData': field with 'extra_data' option cannot be inside a 'oneof'."
        );
    }

    #[test]
    fn test_extra_data_missing_type_option() {
        let desc_set = get_bad_desc_set();
        let msg = find_msg_descriptor(&desc_set, "MessageExtraDataMissingType");
        let err = msg.tlv_layout(&desc_set).unwrap_err();

        assert_eq!(
            err.to_string(),
            "Invalid TLV layout on field 'ext' of message 'MessageExtraDataMissingType': field with 'extra_data' option must explicitly specify a 'type' option (e.g., `[(openprot.tlv.type) = \"[u8]\"]`)."
        );
    }

    #[test]
    fn test_extra_data_unsupported_type() {
        let desc_set = get_bad_desc_set();
        let msg = find_msg_descriptor(&desc_set, "MessageExtraDataUnsupportedType");
        let err = msg.tlv_layout(&desc_set).unwrap_err();

        assert_eq!(
            err.to_string(),
            "Invalid TLV layout on field 'ext' of message 'MessageExtraDataUnsupportedType': 'extra_data' option currently only supports type '[u8]' (got '[u32]')."
        );
    }
}
