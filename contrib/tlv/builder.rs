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

use zerocopy::IntoBytes;
use zerocopy::transmute;
use zerocopy::transmute_mut;

use crate::TlvContainer;
use crate::TlvError;
use crate::TlvFlags;
use crate::TlvHeader;
use crate::TlvItem;
use crate::TlvObject;

/// A builder for creating TLV objects.
pub struct TlvBuilder<'a> {
    header: &'a mut TlvHeader,
    remaining: &'a mut [u32],
}

impl<'a> TlvBuilder<'a> {
    /// Creates a new [`TlvBuilder`] for the given buffer.
    pub fn new<TRoot: TlvObject>(data: &'a mut [u32]) -> Result<(&'a mut TRoot, Self), TlvError> {
        let (header_words, remaining) = data
            .split_first_chunk_mut::<{ crate::word_size_of::<TlvHeader>() }>()
            .ok_or(TlvError)?;
        let header: &mut TlvHeader = transmute_mut!(header_words);
        *header = TlvHeader {
            tag: TRoot::TAG,
            word_len: u16::try_from(crate::word_size_of::<TRoot>()).map_err(|_| TlvError)?,
            reserved: 0,
            flags: TlvFlags::new(),
        };
        let (data_words, remaining) = remaining
            .split_at_mut_checked(crate::word_size_of::<TRoot>())
            .ok_or(TlvError)?;
        let data = TRoot::mut_from_prefix(data_words.as_mut_bytes()).unwrap().0;
        Ok((data, Self { header, remaining }))
    }

    /// Returns a reference to the header of the TLV object being built.
    pub fn header(&self) -> &TlvHeader {
        self.header
    }

    /// Allocates space for a new fixed-size child TLV and returns a mutable reference to it.
    ///
    /// NOTE: On error, the builder is spoiled and finishing it yields an `InvalidBufferError`.
    pub fn add<T: TlvObject>(&mut self) -> Result<&'a mut T, TlvError> {
        let remaining = core::mem::take(&mut self.remaining);
        let (header_words, remaining) = remaining
            .split_first_chunk_mut::<{ crate::word_size_of::<TlvHeader>() }>()
            .ok_or(TlvError)?;
        *header_words = transmute!(TlvHeader {
            tag: T::TAG,
            word_len: u16::try_from(crate::word_size_of::<T>()).map_err(|_| TlvError)?,
            reserved: 0,
            flags: TlvFlags::new(),
        });
        let (data_words, remaining) = remaining
            .split_at_mut_checked(crate::word_size_of::<T>())
            .ok_or(TlvError)?;
        self.remaining = remaining;

        // Update current header length
        let added_words = u16::try_from(crate::word_size_of::<TlvHeader>() + data_words.len())
            .map_err(|_| TlvError)?;
        self.header.word_len = self
            .header
            .word_len
            .checked_add(added_words)
            .ok_or(TlvError)?;

        // Panic is impossible since data_words is guaranteed to be bigger than T
        Ok(T::mut_from_prefix(data_words.as_mut_bytes()).unwrap().0)
    }

    /// Allocates space for a new child TLV, and writes the supplied ext_bytes variable-length
    /// extension. The returned mutable reference can be used to initialize the fixed-size fields of
    /// the TLV.
    ///
    /// NOTE: On error, the builder is spoiled and finishing it yields an `InvalidBufferError`.
    pub fn add_with_ext<T: TlvObject>(&mut self, ext_bytes: &[u8]) -> Result<&'a mut T, TlvError> {
        let remaining = core::mem::take(&mut self.remaining);
        let struct_words = crate::word_size_of::<T>();
        let ext_len = ext_bytes.len();
        let padded_ext_len = ext_len.checked_add(3).map(|n| n & !3).ok_or(TlvError)?;
        let ext_words = padded_ext_len / 4;
        let padding = u8::try_from(padded_ext_len - ext_len).unwrap();

        let total_payload_words = struct_words + ext_words;

        let (header_words, remaining) = remaining
            .split_first_chunk_mut::<{ crate::word_size_of::<TlvHeader>() }>()
            .ok_or(TlvError)?;

        let header = TlvHeader {
            tag: T::TAG,
            word_len: u16::try_from(total_payload_words).map_err(|_| TlvError)?,
            reserved: 0,
            flags: TlvFlags::new().with_padding_bytes(padding),
        };
        *header_words = transmute!(header);

        let (data_words, remaining) = remaining
            .split_at_mut_checked(struct_words)
            .ok_or(TlvError)?;

        let (ext_words_slice, remaining) =
            remaining.split_at_mut_checked(ext_words).ok_or(TlvError)?;

        self.remaining = remaining;

        let ext_bytes_mut = ext_words_slice.as_mut_bytes();
        ext_bytes_mut[..ext_len].copy_from_slice(ext_bytes);
        ext_bytes_mut[ext_len..].fill(0);

        let added_words = u16::try_from(crate::word_size_of::<TlvHeader>() + total_payload_words)
            .map_err(|_| TlvError)?;
        self.header.word_len = self
            .header
            .word_len
            .checked_add(added_words)
            .ok_or(TlvError)?;

        Ok(T::mut_from_prefix(data_words.as_mut_bytes()).unwrap().0)
    }

    /// Allocates space for the fixed size portion of a child TLV, and returns a nested TlvBuilder
    /// that can be used to add children to the child TLV. When all the children have been added,
    /// call `finish_with_parent()` before adding more children to the parent.
    ///
    /// NOTE: Consider using `add_in()` instead, which is less error-prone.
    pub fn add_with_children<T: TlvObject>(
        &mut self,
    ) -> Result<(&'a mut T, TlvBuilder<'a>), TlvError> {
        let remaining = core::mem::take(&mut self.remaining);
        Self::new::<T>(remaining)
    }

    /// Finishes this child builder, restoring and updating the parent builder.
    pub fn finish_with_parent(self, parent: &mut TlvBuilder<'a>) -> Result<(), TlvError> {
        parent.remaining = self.remaining;

        let child_payload_len = usize::from(self.header.word_len);
        let child_total_len_words = crate::word_size_of::<TlvHeader>() + child_payload_len;
        let child_total_len_words_u16 =
            u16::try_from(child_total_len_words).map_err(|_| TlvError)?;
        parent.header.word_len = parent
            .header
            .word_len
            .checked_add(child_total_len_words_u16)
            .ok_or(TlvError)?;
        Ok(())
    }

    /// A closure-based helper built on top of our linear primitives.
    /// Automatically finishes the child builder when the closure completes.
    pub fn add_in<T: TlvObject, F>(&mut self, f: F) -> Result<&'a mut T, TlvError>
    where
        F: FnOnce(&mut T, &mut TlvBuilder<'a>) -> Result<(), TlvError>,
    {
        let (data, mut child_builder) = self.add_with_children::<T>()?;
        f(data, &mut child_builder)?;
        child_builder.finish_with_parent(self)?;
        Ok(data)
    }

    /// Adds a copy of `item` (including its children) as a child of the builder.
    ///
    /// NOTE: On error, the builder is spoiled and finishing it yields an `InvalidBufferError`.
    #[inline(always)]
    pub fn add_copy<T: TlvObject>(&mut self, item: &TlvItem<'_, T>) -> Result<(), TlvError> {
        self.add_copy_container(item.container)
    }

    /// Non-generic implementation of [`Self::add_copy`], to avoid monomorphization bloat.
    fn add_copy_container(&mut self, container: &TlvContainer) -> Result<(), TlvError> {
        let src_words = container.as_words();
        let remaining = core::mem::take(&mut self.remaining);
        let (dest_words, remaining) = remaining
            .split_at_mut_checked(src_words.len())
            .ok_or(TlvError)?;
        dest_words.copy_from_slice(src_words);
        self.remaining = remaining;

        // Update current header length
        let added_words = u16::try_from(src_words.len()).map_err(|_| TlvError)?;
        self.header.word_len = self
            .header
            .word_len
            .checked_add(added_words)
            .ok_or(TlvError)?;
        Ok(())
    }

    /// Finish the builder, making the constructed bytes (or words) available as members of the
    /// returned `TlvBuilderFinisher`.
    pub fn finish(self) -> TlvBuilderFinisher {
        TlvBuilderFinisher {
            start_ptr: self.header as *const _ as *const u32,
            end_ptr: self.remaining.as_mut_ptr(),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct InvalidBufferError;

pub struct TlvBuilderFinisher {
    start_ptr: *const u32,
    end_ptr: *const u32,
}
impl TlvBuilderFinisher {
    #[inline(always)]
    pub fn into_words(self, buf: &[u32]) -> Result<&[u32], InvalidBufferError> {
        // This is all a sanity check that ensures that the user passed the
        // correct buffer in. Hopefully the optimizer is smart enough to remove
        // it.
        if self.start_ptr != buf.as_ptr()
            || self.end_ptr > buf.as_ptr_range().end
            || self.end_ptr < self.start_ptr
        {
            return Err(InvalidBufferError);
        }
        let len = ((self.end_ptr as usize) - (self.start_ptr as usize)) / 4;
        Ok(&buf[..len])
    }
    #[inline(always)]
    pub fn into_bytes(self, buf: &[u32]) -> Result<&[u8], InvalidBufferError> {
        Ok(self.into_words(buf)?.as_bytes())
    }
}
