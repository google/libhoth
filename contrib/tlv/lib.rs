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

//! A simple, zero-copy framework for working with Type-Length-Value (TLV) objects.
//!
//! This crate provides tools to overlay structured views onto raw byte buffers,
//! allowing efficient parsing and creation of TLV structures without unnecessary
//! allocations or copies.
//!
//! # Core Concepts
//!
//! *   [`TlvHeader`]: The common prefix for all TLV objects, containing a 4-byte `tag` and a 2-byte `length` (in 32-bit words).
//! *   [`TlvContainer`]: The contiguous representation of a single TLV object, containing its [`TlvHeader`] and raw payload words.
//! *   [`TlvObject`]: A trait representing a typed TLV structure. The [`tlv_struct!`] macro
//!     is used to define these structs and implement this trait.
//! *   [`TlvData`]: A container representing a sequence of TLVs. It can be used to overlay
//!     on a raw buffer and iterate over the contained TLVs.
//! *   [`TlvItem`]: The parsed representation of a TLV, containing a reference to the [`TlvContainer`],
//!     the parsed object, and any extra data words.
//! *   [`TlvQuery`]: Extension trait for `TlvItem` to allow casting to specific `TlvObject` types
//!     and accessing extension data.
//!
//! # Defining TLV Structures
//!
//! Use the [`tlv_struct!`] macro to define your TLV structures. You must specify:
//! 1.  The name of the struct.
//! 2.  The 4-byte tag as a byte literal (e.g., `*b"FOO_"`).
//! 3.  The type of the extension: either `[u8]` (raw bytes) or `TlvData` (nested TLVs).
//! 4.  The struct definition.
//!
//! ```rust
//! # use tlv::tlv_struct;
//! tlv_struct! { Foo, *b"FOO_", [u8],
//!     #[derive(Debug)]
//!     pub struct Foo {
//!         pub x: u32,
//!         pub y: [u8; 4],
//!     }
//! }
//! ```
//!
//! # Parsing and Iteration
//!
//! To parse a buffer, use [`TlvData::overlay`] and then iterate over it:
//!
//! ```rust
//! # use tlv::{TlvData, TlvAny};
//! # use zerocopy::IntoBytes;
//! let buf: &[u32] = &[]; // Use u32 slice
//! let tlv_data = TlvData::overlay(buf);
//! for item in tlv_data.iter::<TlvAny>() {
//!     println!("Tag: {}, word_len: {}", item.container.header.tag, item.container.header.word_len);
//! }
//! ```

#![cfg_attr(not(test), no_std)]

use bitfield_struct::bitfield;
use core::cmp::min;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;
use zerocopy::transmute_ref;

mod builder;

pub use builder::TlvBuilder;

#[bitfield(u8)]
#[derive(PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct TlvFlags {
    /// Number of trailing padding bytes (0-3) in the last word of the payload.
    /// This is typically used when the variable-length extension is a slice of
    /// u8 or u16 and the exact length is meaningful.
    #[bits(2)]
    pub padding_bytes: u8,
    #[bits(6)]
    __: (),
}

/// Generic TLV header.
///
/// Every TLV object starts with this header, defining its type (tag) and the length
/// of the payload (in 32-bit words) following the header.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout,
)]
#[repr(C)]
pub struct TlvHeader {
    /// The tag identifying the type of the TLV object. Typically represented as a 4-character ASCII string (FourCC).
    pub tag: u32,
    /// The length of the data following this header, in 32-bit words.
    pub word_len: u16,
    /// Reserved; must be zero.
    pub reserved: u8,
    /// Flags; currently only includes the number of padding bytes.
    pub flags: TlvFlags,
}

impl TlvHeader {
    fn ref_from_words_prefix(words: &[u32]) -> Option<(&TlvHeader, &[u32])> {
        let (header_words, rest) = words.split_first_chunk::<{ word_size_of::<TlvHeader>() }>()?;
        Some((transmute_ref!(header_words), rest))
    }

    #[inline(always)]
    pub fn byte_len(&self) -> usize {
        (usize::from(self.word_len) * 4).saturating_sub(usize::from(self.flags.padding_bytes()))
    }
}

/// Returns the size of the type `T` in 32-bit words, asserting at compile time
/// that the size of `T` is a multiple of 4 bytes.
#[inline(always)]
pub const fn word_size_of<T>() -> usize {
    const {
        assert!(
            core::mem::size_of::<T>().is_multiple_of(4),
            "TLV struct size must be a multiple of 4 bytes"
        );
    }
    core::mem::size_of::<T>() / 4
}

/// Generic TLV container.
///
/// This type represents a buffer containing zero or more TLV objects. It is a unsized
/// type and is typically used behind a reference (`&TlvData`) to overlay onto raw byte slices.
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct TlvData {
    data: [u32],
}

/// Zero-sized type that can represent any TLV.
///
/// Used as a generic parameter for [`TlvData::iter`] or [`TlvQuery::cast`] when the
/// specific type is not known or any TLV type is acceptable.
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct TlvAny;

impl TlvObject for TlvAny {
    type Extension = [u8];
    const TAG: u32 = 0;
    fn make_ext<'a>(header: &TlvHeader, extra: &'a [u32]) -> &'a Self::Extension {
        unpad(header, extra)
    }
}

#[doc(hidden)]
pub fn unpad<'a>(header: &TlvHeader, extra: &'a [u32]) -> &'a [u8] {
    let padding_bytes = usize::from(header.flags.padding_bytes());
    let extra_bytes = extra.as_bytes();
    extra_bytes
        .get(..extra_bytes.len().saturating_sub(padding_bytes))
        .unwrap_or(&[])
}

#[derive(Debug, PartialEq, Eq)]
pub struct BadAlignmentError;

impl TlvData {
    /// Constructs a new `TlvData` reference by overlaying onto a word buffer.
    #[inline]
    pub fn overlay(data: &[u32]) -> &Self {
        transmute_ref!(data)
    }

    /// Constructs a new `TlvData` reference by overlaying onto a byte buffer.
    #[inline]
    pub fn overlay_bytes(data: &[u8]) -> Result<&Self, BadAlignmentError> {
        TlvData::ref_from_bytes_with_elems(data, data.len() / 4).map_err(|_| BadAlignmentError)
    }

    /// Returns an iterator over the contained TLV objects of type `T`.
    ///
    /// If `T` is [`TlvAny`], the iterator will yield all TLVs.
    /// Otherwise, it will only yield TLVs with a matching [`TlvObject::TAG`].
    pub fn iter<'a, T: TlvObject>(&'a self) -> TlvIterator<'a, T> {
        TlvIterator {
            data: &self.data,
            target: core::marker::PhantomData,
        }
    }
}

/// Iterator over TLV objects in a [`TlvData`] container.
pub struct TlvIterator<'a, T> {
    data: &'a [u32],
    target: core::marker::PhantomData<T>,
}

/// Contiguous representation of a single TLV object, comprising its header and payload.
///
/// This dynamically sized type (DST) overlays directly onto the raw word buffer,
/// making it possible to access all bytes of the TLV record (e.g. for cryptographic hashing
/// or signature verification) via [`zerocopy::IntoBytes::as_bytes`].
#[repr(C, align(4))]
#[derive(Debug, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct TlvContainer {
    /// The TLV header defining the type and payload length.
    pub header: TlvHeader,
    /// The raw payload words of the TLV object following the header.
    pub payload: [u32],
}

impl TlvContainer {
    /// Returns a byte slice referencing the entire TLV container (header and payload).
    ///
    /// The returned slice is always a multiple of four bytes, regardless of the
    /// padding flags in the header.
    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8] {
        IntoBytes::as_bytes(self)
    }

    /// Returns a 32-bit word slice referencing the entire TLV container (header and payload).
    #[inline(always)]
    pub fn as_words(&self) -> &[u32] {
        <[u32]>::ref_from_bytes(self.as_bytes()).unwrap_or(&[])
    }
}

/// Item returned by [`TlvIterator`].
pub struct TlvItem<'a, T: TlvObject> {
    /// The TLV container containing the header and payload of the object.
    pub container: &'a TlvContainer,
    /// The TLV object itself (parsed struct).
    pub data: &'a T,
    /// Extra data after the parsed struct
    pub extra: &'a [u32],
}

impl<'a, T: TlvObject + 'a> Iterator for TlvIterator<'a, T> {
    type Item = TlvItem<'a, T>;

    fn next(&mut self) -> Option<Self::Item> {
        while !self.data.is_empty() {
            let (header, _) = TlvHeader::ref_from_words_prefix(self.data)?;
            let word_len = usize::from(header.word_len);
            let total_words = word_size_of::<TlvHeader>() + word_len;
            let (container_words, remain) = self.data.split_at_checked(total_words)?;
            let container =
                TlvContainer::ref_from_bytes_with_elems(container_words.as_bytes(), word_len)
                    .ok()?;
            self.data = remain;
            if container.header.tag != T::TAG && T::TAG != TlvAny::TAG {
                continue;
            }
            let Some((data_words, extra)) = container.payload.split_at_checked(word_size_of::<T>())
            else {
                continue;
            };
            let Ok(data) = T::ref_from_bytes(data_words.as_bytes()) else {
                continue;
            };
            return Some(TlvItem {
                container,
                data,
                extra,
            });
        }
        None
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct TlvError;

/// A trait for types that represent a TLV object.
///
/// This trait is typically implemented using the [`tlv_struct!`] macro.
pub trait TlvObject: FromBytes + IntoBytes + Immutable + KnownLayout + Sized {
    /// The extension type for this object.
    ///
    /// This is either `[u8]` for raw payload bytes or [`TlvData`] for nested TLV containers.
    type Extension: ?Sized;

    /// The unique 4-byte tag identifying this TLV type.
    const TAG: u32;

    /// Returns the tag of the object.
    fn get_tag(&self) -> u32 {
        Self::TAG
    }

    /// Helper for making the extension object from raw bytes.
    fn make_ext<'a>(header: &TlvHeader, extra: &'a [u32]) -> &'a Self::Extension;
}

/// Extension trait providing helper methods on [`TlvItem`].
///
/// This trait allows casting a generic `TlvItem` (e.g., returned from `iter::<TlvAny>()`)
/// to a specific `TlvObject` type, and retrieving the extension payload of a `TlvItem`.
pub trait TlvQuery<'a> {
    /// The type of the extension associated with the item.
    type Extension;

    /// Attempts to cast this item to a specific `TlvObject` type `U`.
    ///
    /// Returns `Some(TlvItem<'a, U>)` if the item's tag matches `U::TAG`, and the
    /// data can be parsed as `U`. Otherwise, returns `None`.
    fn cast<U: TlvObject>(&self) -> Option<TlvItem<'a, U>>;

    /// Attempts to cast this item to a specific `TlvObject` type `U`, zero-extending
    /// the data if the payload size (in words) is smaller than the struct.
    ///
    /// Returns `Some(U)` if the item's tag matches `U::TAG`. Otherwise, returns `None`.
    ///
    /// Note: To reduce the code-size cost of monomorphization bloat, this
    /// operates strictly at 32-bit word granularity and ignores
    /// `TlvFlags::padding_bytes`. Any trailing padding bytes in the last word
    /// will be copied as-is into `U`. This should not be a problem, as a
    /// compliant generator will set them to zero.
    fn cast_zero_extended<U: TlvObject>(&self) -> Option<U>;

    /// Returns a reference to the extension payload of this item.
    ///
    /// If the `TlvObject` was defined with `[u8]` extension, this returns `&[u8]`.
    /// If it was defined with `TlvData`, this returns `&TlvData` (for nested TLVs).
    fn ext(&self) -> Self::Extension;
}

impl<'a, T: TlvObject> TlvQuery<'a> for TlvItem<'a, T> {
    type Extension = &'a T::Extension;
    fn cast<U: TlvObject>(&self) -> Option<TlvItem<'a, U>> {
        if self.container.header.tag == U::TAG {
            let (data_words, extra) = self
                .container
                .payload
                .split_at_checked(word_size_of::<U>())?;
            let data = U::ref_from_bytes(data_words.as_bytes()).ok()?;
            Some(TlvItem {
                container: self.container,
                data,
                extra,
            })
        } else {
            None
        }
    }

    fn cast_zero_extended<U: TlvObject>(&self) -> Option<U> {
        if self.container.header.tag == U::TAG {
            let mut result = U::new_zeroed();
            let payload_bytes = self.container.payload.as_bytes();
            let result_bytes = result.as_mut_bytes();
            let copy_limit = min(result_bytes.len(), payload_bytes.len());
            result_bytes[..copy_limit].copy_from_slice(&payload_bytes[..copy_limit]);
            Some(result)
        } else {
            None
        }
    }

    fn ext(&self) -> Self::Extension {
        T::make_ext(&self.container.header, self.extra)
    }
}

/// Defines a TLV struct and implements [`TlvObject`] for it.
///
/// This macro generates a zero-copy representation of a TLV object.
///
/// # Syntax
///
/// ```ignore
/// tlv_struct! { Name, Tag, ExtensionType,
///     [attributes]
///     pub struct Name {
///         pub field1: Type1,
///         ...
///     }
/// }
/// ```
///
/// *   `Name`: The identifier of the struct.
/// *   `Tag`: A 4-byte tag represented as a dereferenced byte array pointer (e.g., `*b"FOO_"`).
/// *   `ExtensionType`: The type of the extension following the struct fields.
///     *   `[u8]`: Raw byte slice.
///     *   [`TlvData`]: Nested TLV container.
/// *   `definition`: The struct definition itself. Must use `#[repr(C)]` style layout
///     safety guarantees (handled by `zerocopy` derives automatically).
///
/// # Examples
///
/// Defining a struct with a raw byte extension:
///
/// ```rust
/// # use tlv::tlv_struct;
/// tlv_struct! { Foo, *b"FOO_", [u8],
///     #[derive(Debug)]
///     pub struct Foo {
///         pub x: u32,
///         pub y: [u8; 4],
///     }
/// }
/// ```
///
/// Defining a struct with nested TLVs:
///
/// ```rust
/// # use tlv::{tlv_struct, TlvData};
/// tlv_struct! { Bar, *b"BAR_", TlvData,
///     #[derive(Debug)]
///     pub struct Bar {
///         pub version: u32,
///     }
/// }
/// ```
#[macro_export]
macro_rules! tlv_struct {
    // This macro doesn't follow "don't repeat yourself" very well.

    // Branch 1: Defines a TLV struct with a raw byte array ([u8]) extension.
    ($name:ident, $tag:expr, [u8], $($definition:tt)*) => {
        // Expand the user's struct definition. Automatically derive the zerocopy traits
        // required to safely overlay this struct onto a byte buffer.
        #[derive(
            zerocopy::FromBytes,
            zerocopy::IntoBytes,
            zerocopy::Immutable,
            zerocopy::KnownLayout,
        )]
        $($definition)*

        const _: () = {
            assert!(
                core::mem::size_of::<$name>() % 4 == 0,
                "TLV struct size must be a multiple of 4 bytes"
            );
        };

        // Implement the TlvObject trait for the generated zero-copy struct.
        impl $crate::TlvObject for $name {
            type Extension = [u8];
            // Convert the tag from little-endian bytes to a u32 constant.
            const TAG: u32 = u32::from_le_bytes($tag);
            // Returns the raw byte slice as the extension type.
            fn make_ext<'a>(header: &$crate::TlvHeader, extra: &'a [u32]) -> &'a Self::Extension {
                $crate::unpad(header, extra)
            }

        }
    };

    // Branch 2: Defines a TLV struct with a nested TLV container (TlvData) extension.
    ($name:ident, $tag:expr, TlvData, $($definition:tt)*) => {
        // Expand the user's struct definition. Same derivations as Branch 1.
        #[derive(
            zerocopy::FromBytes,
            zerocopy::IntoBytes,
            zerocopy::Immutable,
            zerocopy::KnownLayout,
        )]
        $($definition)*

        const _: () = {
            assert!(
                core::mem::size_of::<$name>() % 4 == 0,
                "TLV struct size must be a multiple of 4 bytes"
            );
        };

        // Implement the TlvObject trait for the generated zero-copy struct.
        impl $crate::TlvObject for $name {
            type Extension = $crate::TlvData;
            // Convert the tag from little-endian bytes to a u32 constant.
            const TAG: u32 = u32::from_le_bytes($tag);
            // Overlays a TlvData view onto the remaining bytes to parse them as nested TLVs.
            fn make_ext<'a>(_header: &$crate::TlvHeader, extra: &'a [u32]) -> &'a Self::Extension {
                $crate::TlvData::overlay(extra)
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    tlv_struct! { Parent, *b"PRNT", TlvData,
        #[derive(Debug, PartialEq, Eq)]
        pub struct Parent {
            pub id: u32,
        }
    }

    tlv_struct! { Child, *b"CHLD", [u8],
        #[derive(Debug, PartialEq, Eq)]
        pub struct Child {
            pub value: u32,
        }
    }

    tlv_struct! { MiniFoo, *b"FOO_", [u8],
        #[derive(Debug, PartialEq, Eq)]
        pub struct MiniFoo {
            pub x: u32,
        }
    }

    tlv_struct! { Foo, *b"FOO_", [u8],
        #[derive(Debug, PartialEq, Eq)]
        pub struct Foo {
            pub x: u32,
            pub y: [u8; 4],
        }
    }

    tlv_struct! { Bar, *b"Bar_", TlvData,
        #[derive(Debug, PartialEq, Eq)]
        pub struct Bar {
            pub n: u32,
        }
    }

    tlv_struct! { Baz, *b"Baz_", TlvData,
        #[derive(Debug, PartialEq, Eq)]
        pub struct Baz {
            pub n: u32,
        }
    }

    tlv_struct! { Baf, *b"Baf_", TlvData,
        #[derive(Debug, PartialEq, Eq)]
        pub struct Baf {
            pub a: [u32; 3],
        }
    }

    #[test]
    fn test_build_and_parse_simple() {
        let mut buf = [0u32; 32];

        // Build Parent and Child
        let (parent, mut builder) = TlvBuilder::new::<Parent>(&mut buf).unwrap();
        parent.id = 100;

        let child = builder.add::<Child>().unwrap();
        child.value = 200;

        let result_bytes = builder.finish().into_bytes(&buf).unwrap();
        assert_eq!(result_bytes.len(), 24);

        // Parse back
        let data = TlvData::overlay_bytes(result_bytes).unwrap();

        let mut parent_iter = data.iter::<Parent>();
        let parent_item = parent_iter.next().unwrap();
        assert!(parent_iter.next().is_none());

        assert_eq!(parent_item.container.header.tag, Parent::TAG);
        assert_eq!(parent_item.data.id, 100);

        // Parse Child from Parent's extension
        let mut child_iter = parent_item.ext().iter::<Child>();
        let child_item = child_iter.next().expect("Should find Child");
        assert!(child_iter.next().is_none());

        assert_eq!(child_item.container.header.tag, Child::TAG);
        assert_eq!(child_item.data.value, 200);
    }

    #[test]
    fn test_parsing() {
        // Flat binary buffer matching the layout in the test, with the updated header structure:
        // - reserved byte at offset 6 is 0x00
        // - flags byte at offset 7 contains padding_bytes
        let buf: [u8; 124] = [
            // Bar Header and data (tag: "Bar_", len: 29 words, n: 5)
            b'B', b'a', b'r', b'_', 0x1d, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
            // Foo 1 Header and data (tag: "FOO_", len: 3 words, x: 20, y: [1, 2, 3, 4], ext: [5, 6, 7, 8])
            b'F', b'O', b'O', b'_', 0x03, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x01, 0x02,
            0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            // Foo 2 Header and data (tag: "FOO_", len: 2 words, x: 30, y: [10, 20, 30, 40], ext = [])
            b'F', b'O', b'O', b'_', 0x02, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x00, 0x00, 0x0a, 0x14,
            0x1e, 0x28,
            // Foo 3 Header and data (tag: "FOO_", len: 3 words, reserved: 0, flags: 1, x: 40, y: [11, 12, 13, 14], ext: [15, 16, 17], padded with one zero)
            b'F', b'O', b'O', b'_', 0x03, 0x00, 0x00, 0x01, 0x28, 0x00, 0x00, 0x00, 0x0b, 0x0c,
            0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x00,
            // Foo 4 Header and data (tag: "FOO_", len: 4 words, reserved: 0, flags: 3, x: 50, y: [21, 22, 23, 24], ext: [25, 26, 27, 28, 29], padded with three zeros)
            b'F', b'O', b'O', b'_', 0x04, 0x00, 0x00, 0x03, 0x32, 0x00, 0x00, 0x00, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 0x00, 0x00, 0x00,
            // Baz Header and data (tag: "Baz_", len: 1 word, n: 60)
            b'B', b'a', b'z', b'_', 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00,
            // Baf Header and data (tag: "Baf_", len: 3 words, a: [237482734, 19263432, 81823823])
            b'B', b'a', b'f', b'_', 0x03, 0x00, 0x00, 0x00, 0xee, 0xb2, 0x27, 0x0e, 0xc8, 0xef,
            0x25, 0x01, 0x4f, 0x88, 0xe0, 0x04,
        ];
        let buf_words: [u32; 31] = zerocopy::transmute!(buf);

        // Overlay TlvData and parse the outer container
        let t = TlvData::overlay(&buf_words);

        let mut bar_iter = t.iter::<Bar>();
        let bar_item = bar_iter.next().expect("Should have one Bar item");
        assert!(bar_iter.next().is_none());

        assert_eq!(bar_item.container.header.tag, Bar::TAG);
        assert_eq!(bar_item.container.header.word_len, 29);
        assert_eq!(bar_item.data.n, 5);
        assert_eq!(bar_item.container.as_bytes(), &buf);
        assert_eq!(bar_item.container.as_words(), &buf_words);

        // Iterate over Bar's extensions
        let mut ext_iter = bar_item.ext().iter::<TlvAny>();

        // First extension: Foo
        let ext1 = ext_iter.next().expect("Should have first extension");
        assert_eq!(ext1.container.header.tag, Foo::TAG);
        assert_eq!(ext1.container.header.word_len, 3);
        assert_eq!(ext1.container.as_bytes(), &buf[12..32]);
        assert_eq!(ext1.container.as_words(), &buf_words[3..8]);
        let foo1 = ext1.cast::<Foo>().expect("Should cast to Foo");
        assert_eq!(foo1.data.x, 20);
        assert_eq!(foo1.data.y, [1, 2, 3, 4]);
        assert_eq!(foo1.ext(), &[5, 6, 7, 8]);

        // Second extension: Foo
        let ext2 = ext_iter.next().expect("Should have second extension");
        assert_eq!(ext2.container.header.tag, Foo::TAG);
        assert_eq!(ext2.container.header.word_len, 2);
        let foo2 = ext2.cast::<Foo>().expect("Should cast to Foo");
        assert_eq!(foo2.data.x, 30);
        assert_eq!(foo2.data.y, [10, 20, 30, 40]);
        assert_eq!(foo2.ext(), &[] as &[u8]);

        // Third extension: Foo
        let ext3 = ext_iter.next().expect("Should have third extension");
        assert_eq!(ext3.container.header.tag, Foo::TAG);
        assert_eq!(ext3.container.header.word_len, 3);
        let foo3 = ext3.cast::<Foo>().expect("Should cast to Foo");
        assert_eq!(foo3.data.x, 40);
        assert_eq!(foo3.data.y, [11, 12, 13, 14]);
        assert_eq!(foo3.ext(), &[15, 16, 17]);

        // Fourth extension: Foo
        let ext4 = ext_iter.next().expect("Should have fourth extension");
        assert_eq!(ext4.container.header.tag, Foo::TAG);
        assert_eq!(ext4.container.header.word_len, 4);
        let foo4 = ext4.cast::<Foo>().expect("Should cast to Foo");
        assert_eq!(foo4.data.x, 50);
        assert_eq!(foo4.data.y, [21, 22, 23, 24]);
        assert_eq!(foo4.ext(), &[25, 26, 27, 28, 29]);

        // Fifth extension: Baz
        let ext5 = ext_iter.next().expect("Should have fifth extension");
        assert_eq!(ext5.container.header.tag, Baz::TAG);
        assert_eq!(ext5.container.header.word_len, 1);
        let baz5 = ext5.cast::<Baz>().expect("Should cast to Baz");
        assert_eq!(baz5.data.n, 60);
        // Baz's extension type is TlvData, check that it is empty
        assert!(baz5.ext().iter::<TlvAny>().next().is_none());

        // Sixth extension: Baf
        let ext6 = ext_iter.next().expect("Should have sixth extension");
        assert_eq!(ext6.container.header.tag, Baf::TAG);
        assert_eq!(ext6.container.header.word_len, 3);
        let baf6 = ext6.cast::<Baf>().expect("Should cast to Baf");
        assert_eq!(baf6.data.a, [237482734, 19263432, 81823823]);

        // No further extensions should exist
        assert!(ext_iter.next().is_none());

        // Iterate over only the Foos
        let mut foo_iter = bar_item.ext().iter::<Foo>();
        assert_eq!(foo_iter.next().unwrap().data, foo1.data);
        assert_eq!(foo_iter.next().unwrap().data, foo2.data);
        assert_eq!(foo_iter.next().unwrap().data, foo3.data);
        assert_eq!(foo_iter.next().unwrap().data, foo4.data);
        assert!(foo_iter.next().is_none());

        // Iterate over only the Bazs
        let mut baz_iter = bar_item.ext().iter::<Baz>();
        assert_eq!(baz_iter.next().unwrap().data, baz5.data);
        assert!(baz_iter.next().is_none());

        // Iterate over only the Bafs
        let mut baf_iter = bar_item.ext().iter::<Baf>();
        assert_eq!(baf_iter.next().unwrap().data, baf6.data);
        assert!(baf_iter.next().is_none());
    }

    #[test]
    fn test_builder_closure() {
        let mut buf = [0u32; 100];
        let (bar, mut tlv) = TlvBuilder::new::<Bar>(&mut buf).unwrap();
        *bar = Bar { n: 5 };
        tlv.add_in::<Baz, _>(|baz, tlv| {
            *baz = Baz { n: 60 };
            *tlv.add::<Foo>()? = Foo {
                x: 20,
                y: [1, 2, 3, 4],
            };
            Ok(())
        })
        .unwrap();
        *tlv.add::<Foo>().unwrap() = Foo {
            x: 30,
            y: [10, 20, 30, 40],
        };
        let result_bytes = tlv.finish().into_bytes(&buf).unwrap();

        let expected_bytes_explicit = &[
            // Bar Header and data (tag: "Bar_", len: 12 words, n: 5)
            b'B', b'a', b'r', b'_', 0x0c, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
            // Baz Header and data (tag: "Baz_", len: 5 words, n: 60)
            b'B', b'a', b'z', b'_', 0x05, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00,
            // Foo Header and data inside baz (tag: "FOO_", len: 2 words, x: 20, y: [1, 2, 3, 4])
            b'F', b'O', b'O', b'_', 0x02, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x01, 0x02,
            0x03, 0x04,
            // Foo Header and data inside bar(tag: "FOO_", len: 2 words, x: 30, y: [10, 20, 30, 40])
            b'F', b'O', b'O', b'_', 0x02, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x00, 0x00, 0x0a, 0x14,
            0x1e, 0x28,
        ];
        assert_eq!(result_bytes, expected_bytes_explicit);

        // Overlay TlvData and parse the built container to verify round-trip correctness
        let t = TlvData::overlay_bytes(result_bytes).unwrap();

        let mut bar_iter = t.iter::<Bar>();
        let bar_item = bar_iter.next().expect("Should have one Bar item");
        assert!(bar_iter.next().is_none());

        assert_eq!(bar_item.container.header.tag, Bar::TAG);
        assert_eq!(bar_item.container.header.word_len, 12);
        assert_eq!(bar_item.data.n, 5);

        // Iterate over Bar's extensions
        let mut ext_iter = bar_item.ext().iter::<TlvAny>();

        // First extension: Baz
        let ext_baz = ext_iter.next().expect("Should have Baz extension");
        assert_eq!(ext_baz.container.header.tag, Baz::TAG);
        assert_eq!(ext_baz.container.header.word_len, 5);
        let baz_item = ext_baz.cast::<Baz>().expect("Should cast to Baz");
        assert_eq!(baz_item.data.n, 60);

        {
            // Baz's child: Foo (nested inside Baz)
            let mut baz_ext_iter = baz_item.ext().iter::<TlvAny>();
            let ext_foo_in_baz = baz_ext_iter.next().expect("Should have Foo inside Baz");
            assert_eq!(ext_foo_in_baz.container.header.tag, Foo::TAG);
            assert_eq!(ext_foo_in_baz.container.header.word_len, 2);
            let foo_in_baz = ext_foo_in_baz
                .cast::<Foo>()
                .expect("Should cast to Foo inside Baz");
            assert_eq!(foo_in_baz.data.x, 20);
            assert_eq!(foo_in_baz.data.y, [1, 2, 3, 4]);
            assert!(baz_ext_iter.next().is_none());
        }

        // Second extension: Foo (flat child of Bar)
        let ext_foo_in_bar = ext_iter.next().expect("Should have Foo inside Bar");
        assert_eq!(ext_foo_in_bar.container.header.tag, Foo::TAG);
        assert_eq!(ext_foo_in_bar.container.header.word_len, 2);
        let foo_in_bar = ext_foo_in_bar
            .cast::<Foo>()
            .expect("Should cast to Foo inside Bar");
        assert_eq!(foo_in_bar.data.x, 30);
        assert_eq!(foo_in_bar.data.y, [10, 20, 30, 40]);
        assert!(ext_iter.next().is_none());
    }

    #[test]
    fn test_builder_overflow() {
        // Buffer big enough to hold the large TLVs.
        // 70000 u32 words.
        let mut buf = vec![0u32; 70000];
        let (bar, mut tlv) = TlvBuilder::new::<Bar>(&mut buf).unwrap();
        *bar = Bar { n: 5 };

        // We add 16382 Foo objects (4 words each = 65528 words) and 2 Baz objects
        // (3 words each = 6 words total).
        // This results in a child Baz payload of exactly 65535 words, which fits in u16.
        // But the child total length (payload + 2 words header) is 65537 words,
        // which overflows u16.
        let res = tlv.add_in::<Baz, _>(|baz, child_tlv| {
            *baz = Baz { n: 42 };
            for _ in 0..16382 {
                child_tlv.add::<Foo>()?;
            }
            child_tlv.add::<Baz>()?;
            child_tlv.add::<Baz>()?;
            Ok(())
        });

        // The finish_with_parent call must catch the u16 overflow and return Err(TlvError).
        assert_eq!(res.unwrap_err(), TlvError);
    }

    #[test]
    fn test_cast_lifetime() {
        let mut buf = [0u32; 16];
        let (foo, tlv) = TlvBuilder::new::<Foo>(&mut buf).unwrap();
        *foo = Foo { x: 42, y: [0; 4] };
        let result_bytes = tlv.finish().into_bytes(&buf).unwrap();
        let data = TlvData::overlay_bytes(result_bytes).unwrap();

        // Verify that we can cast and collect generic TLV items using standard
        // iterator combinators.
        let foos: Vec<TlvItem<'_, Foo>> = data
            .iter::<TlvAny>()
            .filter_map(|item| item.cast::<Foo>())
            .collect();

        assert_eq!(foos.len(), 1);
        assert_eq!(foos[0].data, &Foo { x: 42, y: [0; 4] });
    }

    #[test]
    fn test_malformed_tlv_streams() {
        // 1. Unaligned byte buffer passed to overlay_bytes must fail with BadAlignmentError
        let aligned_buf = [0u8; 16];
        let unaligned_slice = &aligned_buf[1..13]; // Offset by 1 byte -> unaligned!
        assert!(TlvData::overlay_bytes(unaligned_slice).is_err());

        // 2. Buffer too short for a single header (header is 8 bytes = 2 words)
        let too_short_words = [0u32; 1]; // Only 1 word (4 bytes)
        let data = TlvData::overlay(&too_short_words);
        assert!(data.iter::<Foo>().next().is_none()); // Must fail gracefully, not panic!

        // 3. Header claims a payload length of 5 words, but buffer ends immediately after header
        let header_only = [
            u32::from_le_bytes(*b"FOO_"),
            0x00000005, // word_len: 5, but no payload follows
        ];
        let data = TlvData::overlay(&header_only);
        assert!(data.iter::<Foo>().next().is_none()); // Must fail gracefully (out-of-bounds)

        // 4. Header claims a payload length of 1 word, but the Foo struct requires at least 2 words
        let header_too_small = [
            u32::from_le_bytes(*b"FOO_"),
            0x00000001, // word_len: 1, which is smaller than the Foo struct size (2 words)!
            0x00000014, // payload element 1
        ];
        let data = TlvData::overlay(&header_too_small);
        assert!(data.iter::<Foo>().next().is_none()); // Must fail gracefully (too small for struct)

        // 5. Completely empty buffer
        let empty_words: [u32; 0] = [];
        let data = TlvData::overlay(&empty_words);
        assert!(data.iter::<TlvAny>().next().is_none());
    }

    #[test]
    fn test_iterator_underflow_skips() {
        // Create a buffer containing:
        // 1. A MiniFoo object (tag: FOO_, len: 1 word, x: 42) -- this represents an underflow for Foo
        // 2. A Foo object (tag: FOO_, len: 2 words, x: 99, y: [9, 9, 9, 9]) -- a perfectly valid Foo
        let buf = [
            // MiniFoo Header & Payload
            u32::from_le_bytes(*b"FOO_"),
            0x00000001, // word_len: 1
            42,         // MiniFoo.x
            // Foo Header & Payload
            u32::from_le_bytes(*b"FOO_"),
            0x00000002,                       // word_len: 2
            99,                               // Foo.x
            u32::from_le_bytes([9, 9, 9, 9]), // Foo.y
        ];

        let data = TlvData::overlay(&buf);

        // We expect that iterating over Foo records will NOT abort on the first underflowed record.
        // Even if the first record cannot be yielded as a full TlvItem<'_, Foo> (because it is too short),
        // the iterator should advance past it and successfully yield the second, perfectly valid Foo record.
        let mut iter = data.iter::<Foo>();
        let second_item = iter
            .next()
            .expect("Should not terminate prematurely; should yield the second valid Foo");
        assert_eq!(second_item.data.x, 99);
        assert_eq!(second_item.data.y, [9, 9, 9, 9]);
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_casting_varied_sizes() {
        let mut buf = [0u32; 16];

        // =====================================================================
        // Scenario 1: Payload is 8 bytes (Foo) ---
        // =====================================================================
        let (foo, tlv) = TlvBuilder::new::<Foo>(&mut buf).unwrap();
        *foo = Foo {
            x: 42,
            y: [1, 2, 3, 4],
        };
        let data = TlvData::overlay(tlv.finish().into_words(&buf).unwrap());
        let item = data.iter::<TlvAny>().next().unwrap();

        // --- Case 1A: Exact Match (Target: Foo) ---

        // `cast_zero_extended` succeeds and returns an owned, fully-populated struct.
        let foo_cast_ze: Foo = item.cast_zero_extended::<Foo>().unwrap();
        assert_eq!(foo_cast_ze.x, 42);
        assert_eq!(foo_cast_ze.y, [1, 2, 3, 4]);

        // `cast` succeeds and returns a TlvItem referencing the struct with no extra extension.
        let foo_cast: TlvItem<'_, Foo> = item.cast::<Foo>().unwrap();
        assert_eq!(foo_cast.data.x, 42);
        assert_eq!(foo_cast.data.y, [1, 2, 3, 4]);
        assert!(foo_cast.extra.is_empty());

        // `iter::<Foo>()` succeeds and yields the exact match item with no extra extension.
        let mut iter_exact = data.iter::<Foo>();
        let item_exact = iter_exact.next().unwrap();
        assert_eq!(item_exact.data.x, 42);
        assert_eq!(item_exact.data.y, [1, 2, 3, 4]);
        assert!(item_exact.extra.is_empty());
        assert!(iter_exact.next().is_none());

        // --- Case 1B: Shrunk Match / Overflow (Target: MiniFoo) ---

        // `cast_zero_extended` succeeds, returning an owned struct and discarding excess bytes.
        let foo_shrunk_ze: MiniFoo = item.cast_zero_extended::<MiniFoo>().unwrap();
        assert_eq!(foo_shrunk_ze.x, 42);

        // `cast` succeeds, returning a TlvItem referencing MiniFoo, with the excess bytes placed in `extra`.
        let foo_shrunk = item.cast::<MiniFoo>().unwrap();
        assert_eq!(foo_shrunk.data.x, 42);
        assert_eq!(foo_shrunk.extra, &[u32::from_le_bytes([1, 2, 3, 4])]);

        // `iter::<MiniFoo>()` succeeds, yielding a TlvItem referencing MiniFoo, with the excess bytes placed in `extra`.
        let mut iter_shrunk = data.iter::<MiniFoo>();
        let item_shrunk = iter_shrunk.next().unwrap();
        assert_eq!(item_shrunk.data.x, 42);
        assert_eq!(item_shrunk.extra, &[u32::from_le_bytes([1, 2, 3, 4])]);
        assert!(iter_shrunk.next().is_none());

        // --- Case 1C: Mismatched Tag (Target: Parent) ---

        // All casting operations fail (return None) due to tag mismatch.
        assert!(item.cast_zero_extended::<Parent>().is_none());
        assert!(item.cast::<Parent>().is_none());

        // =====================================================================
        // Scenario 2: Payload is 4 bytes (MiniFoo)
        // =====================================================================
        let (mini, tlv) = TlvBuilder::new::<MiniFoo>(&mut buf).unwrap();
        *mini = MiniFoo { x: 99 };
        let data = TlvData::overlay(tlv.finish().into_words(&buf).unwrap());
        let item = data.iter::<TlvAny>().next().unwrap();

        // --- Case 2A: Extended Match / Underflow (Target: Foo) ---

        // `cast_zero_extended` succeeds by zero-padding the missing fields of the target struct.
        let foo_extended_ze: Foo = item.cast_zero_extended::<Foo>().unwrap();
        assert_eq!(foo_extended_ze.x, 99);
        assert_eq!(foo_extended_ze.y, [0, 0, 0, 0]);

        // `cast` fails (returns None) because the payload is smaller than the target struct.
        assert!(item.cast::<Foo>().is_none());

        // `iter::<Foo>()` skips the item (returns None) because the payload is smaller than the target struct.
        let mut iter_extended = data.iter::<Foo>();
        assert!(iter_extended.next().is_none());

        // --- Case 2B: Mismatched Tag (Target: Parent) ---

        // All casting operations fail (return None) due to tag mismatch.
        assert!(item.cast_zero_extended::<Parent>().is_none());
        assert!(item.cast::<Parent>().is_none());
    }

    #[test]
    fn test_builder_with_slice() {
        let mut buf_vec = vec![0u32; 32];
        let slice: &mut [u32] = &mut buf_vec;

        let (parent, mut builder) = TlvBuilder::new::<Parent>(slice).unwrap();
        parent.id = 100;

        let child = builder.add::<Child>().unwrap();
        child.value = 200;

        // This should fail to compile before the fix:
        let result_bytes = builder.finish().into_bytes(slice).unwrap();
        assert_eq!(result_bytes.len(), 24);

        let data = TlvData::overlay_bytes(result_bytes).unwrap();
        let parent_item = data.iter::<Parent>().next().unwrap();
        assert_eq!(parent_item.data.id, 100);
        let child_item = parent_item.ext().iter::<Child>().next().unwrap();
        assert_eq!(child_item.data.value, 200);
    }

    tlv_struct! { FooV1, *b"FOO_", [u8],
        #[derive(Debug, PartialEq, Eq, Default)]
        pub struct FooV1 {
            pub a: u32,
            pub b: u32,
        }
    }

    tlv_struct! { FooV2, *b"FOO_", [u8],
        #[derive(Debug, PartialEq, Eq, Default)]
        pub struct FooV2 {
            pub a: u32,
            pub b: u32,
            pub c: u32,
        }
    }

    #[test]
    fn test_forward_compatibility() {
        let mut buf = [0u32; 32];

        // V2 firmware writes FooV2
        let (foo_v2, tlv) = TlvBuilder::new::<FooV2>(&mut buf).unwrap();
        foo_v2.a = 100;
        foo_v2.b = 200;
        foo_v2.c = 300;
        let result_bytes = tlv.finish().into_bytes(&buf).unwrap();

        // V1 firmware reads it as FooV1
        let data = TlvData::overlay_bytes(result_bytes).unwrap();
        let mut iter = data.iter::<FooV1>();
        let item = iter.next().expect("Should be able to parse as FooV1");
        assert!(iter.next().is_none());

        assert_eq!(item.data.a, 100);
        assert_eq!(item.data.b, 200);

        // The extra field 'c' (300) should be in the extension bytes
        let ext_bytes = item.ext();
        assert_eq!(ext_bytes.len(), 4);
        let c_val = u32::from_le_bytes(ext_bytes.try_into().unwrap());
        assert_eq!(c_val, 300);
    }

    #[test]
    fn test_backward_compatibility_fails_directly() {
        let mut buf = [0u32; 32];

        // V1 firmware writes FooV1 (2 words)
        let (foo_v1, tlv) = TlvBuilder::new::<FooV1>(&mut buf).unwrap();
        foo_v1.a = 100;
        foo_v1.b = 200;
        let result_bytes = tlv.finish().into_bytes(&buf).unwrap();

        // V2 firmware tries to read it as FooV2 (expects 3 words)
        let data = TlvData::overlay_bytes(result_bytes).unwrap();
        let mut iter = data.iter::<FooV2>();

        // This returns None because the payload is too short for FooV2
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_forward_compatibility_padded() {
        let mut buf = [0u32; 32];

        // V1 firmware writes FooV1 (2 words)
        let (foo_v1, tlv) = TlvBuilder::new::<FooV1>(&mut buf).unwrap();
        foo_v1.a = 100;
        foo_v1.b = 200;
        let result_bytes = tlv.finish().into_bytes(&buf).unwrap();

        // V2 firmware reads it as TlvAny first, then uses cast_zero_extended
        let data = TlvData::overlay_bytes(result_bytes).unwrap();
        let mut iter = data.iter::<TlvAny>();
        let item = iter.next().expect("Should find the TLV");
        assert!(iter.next().is_none());

        // Read as FooV2, which should succeed and 0-initialize 'c'
        let foo_v2 = item
            .cast_zero_extended::<FooV2>()
            .expect("Should read as FooV2");
        assert_eq!(foo_v2.a, 100);
        assert_eq!(foo_v2.b, 200);
        assert_eq!(foo_v2.c, 0); // 'c' is 0-initialized
    }
}
