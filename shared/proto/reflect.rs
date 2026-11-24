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

//! Reflection and metadata helpers for Protobuf types.

use descriptor_rust_proto::field_descriptor_proto::Type;

/// Metadata about a primitive Protobuf field type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrimitiveInfo {
    /// The size in bytes of the primitive type.
    pub size: usize,
    /// Whether the primitive type is signed.
    pub is_signed: bool,
    /// Whether the primitive type is a floating-point type.
    pub is_float: bool,
}

/// Extension trait for Protobuf [`Type`].
pub trait TypeExt {
    /// Returns the primitive metadata for this type, or `None` if the type is not a packable primitive.
    fn primitive_info(&self) -> Option<PrimitiveInfo>;
}

impl TypeExt for Type {
    fn primitive_info(&self) -> Option<PrimitiveInfo> {
        match *self {
            Type::Double => Some(PrimitiveInfo {
                size: 8,
                is_signed: true,
                is_float: true,
            }),
            Type::Float => Some(PrimitiveInfo {
                size: 4,
                is_signed: true,
                is_float: true,
            }),
            Type::Int64 | Type::Sint64 | Type::Sfixed64 => Some(PrimitiveInfo {
                size: 8,
                is_signed: true,
                is_float: false,
            }),
            Type::Uint64 | Type::Fixed64 => Some(PrimitiveInfo {
                size: 8,
                is_signed: false,
                is_float: false,
            }),
            Type::Int32 | Type::Sint32 | Type::Sfixed32 => Some(PrimitiveInfo {
                size: 4,
                is_signed: true,
                is_float: false,
            }),
            Type::Uint32 | Type::Fixed32 => Some(PrimitiveInfo {
                size: 4,
                is_signed: false,
                is_float: false,
            }),
            Type::Bool => Some(PrimitiveInfo {
                size: 1,
                is_signed: false,
                is_float: false,
            }),
            Type::Enum => Some(PrimitiveInfo {
                size: 4,
                is_signed: true,
                is_float: false,
            }),
            _ => None,
        }
    }
}
