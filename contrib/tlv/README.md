# Zero-Copy Type-Length-Value (TLV) Wire Format

This document defines the binary wire format of the Type-Length-Value (TLV)
serialization framework used in `mutask`.

---

## Design Philosophy

The TLV framework is designed for high-performance, resource-constrained
environments, in particular embedded systems with limited memory and storage.
Its core design goals are:
1. **Zero-Copy Parsing:** Structured views are overlaid directly onto raw
   byte/word buffers using the `zerocopy` crate, eliminating parsing
   allocations and copies.
2. **Word Alignment:** All headers, payloads, and nested elements are strictly
   aligned to **32-bit (4-byte) word boundaries** to match the native alignment
   of 32-bit CPUs (e.g., RV32IMC, ARMv7-M) and maximize memory access efficiency.
3. **Robust Schema Evolution:** The wire format natively supports forward and
   backward compatibility via explicit payload length fields and zero-extended
   casting.

---

## Protobuf Schema & Code Generation

Rather than authoring TLV structures manually in Rust, schemas can be defined
using standard Protocol Buffers (Protobuf) annotated with custom layout options
(such as FourCC tags, offsets, and bit ranges).

A code generator (`tlv_codegen`) automatically compiles these `.proto` definitions
into the corresponding zero-copy Rust structures, and a serialization pipeline
(`proto_conv`) is provided to pack host-side Protobuf messages into the aligned
binary wire format.

For a comprehensive guide on schema definition, custom options, and the
serialization pipeline, see [Protobuf Schema & Code Generation](PROTOBUF.md).

---

## Wire Layout Overview

Every TLV object consists of a **fixed 8-byte (2-word) header**, followed by a
**variable-length payload** whose size is a multiple of 4 bytes.

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            Tag (u32)                          | Word 0 (Header)
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Word Length (u16)     | Reserved (u8) |  Flags (u8)   | Word 1 (Header)
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               | Word 2 (Payload: Fixed Struct)
+                     Fixed-Size Struct (U)                     +
|                                                               | Word N
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               | Word N+1 (Payload: Extension)
+                     Variable-Length Extension                 +
|                                                               | Word N+M
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

---

## Header Fields

The header is exactly 8 bytes long and contains the following fields:

### 1. Tag (`u32`) - 4 Bytes (Offset 0)
* Identifies the type of the TLV object, typically as a 4-character ASCII FourCC.
* **Byte Order:** The ASCII characters are laid out sequentially from offset 0
  to 3 (e.g., `*b"FOO_"` is stored on the wire as the bytes `46 4F 4F 5F`).
* **Integer Value:** Interpreted in Rust as a little-endian `u32` (via
  `u32::from_le_bytes`). For example, `*b"FOO_"` yields the integer
  `0x5F4F4F46`.

### 2. Word Length (`u16`) - 2 Bytes (Offset 4)
* The length of the payload following this header, measured in **32-bit words**
  (not bytes).
* A value of `0` indicates that no payload follows the header.

### 3. Reserved (`u8`) - 1 Byte (Offset 6)
* Reserved for future protocol additions.
* **Must be set to `0`** by generators and ignored by readers.

### 4. Flags (`u8`) - 1 Byte (Offset 7)
* Packed bitfield configuration.
* **Padding Bytes (Bits 0-1):** A 2-bit value (0 to 3) indicating the number of
  trailing padding bytes in the last word of the payload. This is used when the
  variable-length extension is a slice of bytes or half-words (e.g., `[u8]` or
  `[u16]`) and the exact byte length is meaningful.
* **Reserved (Bits 2-7):** Must be set to `0`.

---

## Payload Structure

The payload starts immediately after the 8-byte header and is divided into two
logical sections:

1. **Fixed-Size Struct (`U`):** A fixed-size struct containing the static
   fields of the TLV object. Its size in bytes must be a multiple of 4.
2. **Variable-Length Extension:** Any remaining words in the payload after the
   fixed struct.

### Length Calculations

The payload contains the **Fixed Struct** followed by the **Extension**. Their
sizes are derived from the header's `Word Length` and `Padding Bytes` as follows:

```text
payload_len   = header.word_len * 4
struct_len    = sizeof(U).next_multiple_of(4)
extension_len = payload_len - struct_len - header.flags.padding_bytes
```

## Extension Types

The variable-length extension can represent two different types of data:

### 1. Extra Data
When a TLV record is defined with extra data (annotated with `(openprot.tlv.extra_data) = true`
in Protobuf, or `type Extension = [u8]` in Rust), the payload following the fixed struct
is interpreted as raw bytes or a typed slice.
* The generator fills the extra data bytes, pads the final word to 4 bytes with
  zeros, and sets `Padding Bytes` in the header flags to the number of padding
  bytes added (0-3).
* Readers retrieve the unpadded slice via `TlvItem::ext()` or generated field accessors.

### 2. Nested TLV Container (`TlvData`)
If the TLV object is defined with a `TlvData` extension, the extension is
interpreted as a sequence of zero or more nested TLV objects.
* Because nested TLVs are themselves structured and word-aligned, **no
  byte-level padding is used** at the container level. The `Padding Bytes`
  field in the parent header flags **must be set to `0`**.
* The nested TLVs are laid out sequentially within the parent's extension
  words, allowing recursive, zero-copy parsing.

---

## Compatibility & Schema Evolution

The TLV framework supports robust schema evolution. Here are the mechanisms and
rules for modifying structures safely:

### 1. Adding New TLV Records
* New TLV record types (with unique tags) can be freely added to a stream.
* Existing readers using `TlvIterator` will automatically skip unrecognized
  tags by reading the `word_len` field in the header to jump to the next record,
  ensuring full backward compatibility.

### 2. Modifying Existing Structs (Field Additions)
New fields can be appended to the end of an existing fixed struct `U`, subject to
the following strict rules and compatibility behaviors:

#### Rules & Constraints:
* **No Variable-Length Extensions:** Fields can **only** be added to `U` if the
  record does not carry variable-length data (such as nested TLV sub-records or
  an `extra_data` payload).
  * *Why:* Appending fields to `U` increases `sizeof(U)`, shifting the start
    offset of the extension. A newer reader will look for the extension at the
    new offset, failing to parse or misinterpreting data generated by older writers.
* **Future Constraint:** Adding fields to `U` **prevents** subsequent introduction
  of nested TLVs or variable-length `extra_data`, as any further field additions
  would break the start offset of the variable-length data across versions.

#### Backward Compatibility (Underflow):
If a reader compiled with a newer, larger version of struct `U` receives a
payload generated by an older, smaller version, the payload length will be
smaller than `sizeof(U)`:
* The `cast_zero_extended` method allocates `U` on the stack, initializes it to
  all-zeros (`U::new_zeroed()`), and copies the available payload bytes.
* The new fields at the end of `U` naturally remain zeroed, allowing safe,
  backward-compatible default behavior.

#### Forward Compatibility (Overflow):
If an older reader receives a newer, larger payload:
* **For regular casting (`cast`):** The excess words are cleanly separated into
  the `extra` field, allowing the reader to access the base struct while
  ignoring or forwarding the new fields.
* **For zero-extended casting (`cast_zero_extended`):** The method copies only
  the bytes that fit into the target struct `U` and discards the excess bytes,
  preventing overflow or parser failure.

---

## Wire Examples

### Example 1: Simple Struct with Raw Byte Extension
Consider a TLV object defined as:
```rust
tlv_struct! { Foo, *b"FOO_", [u8],
    pub struct Foo {
        pub value: u32,
    }
}
```
If we construct a `Foo` with `value = 0x12345678` and a raw byte extension of
`[0xAA, 0xBB, 0xCC]` (3 bytes):
* The fixed struct size is 4 bytes (1 word).
* The extension is 3 bytes, requiring 1 word (4 bytes) with 1 byte of padding.
* Total payload is 2 words (`word_len = 2`).
* `Padding Bytes` is `1`.

#### Byte Layout:
```hexdump
Address/Word  Offset  Byte Values         Description
--------------------------------------------------------------------------------
Word 0        00..03  46 4F 4F 5F         Tag: 'FOO_' (0x5F4F4F46)
Word 1        04..05  02 00               Word Length: 2 (payload is 8 bytes)
              06      00                  Reserved: 0
              07      01                  Flags: padding_bytes = 1 (bits 0-1)
Word 2        08..11  78 56 34 12         Foo.value: 0x12345678 (little-endian)
Word 3        12..14  AA BB CC            Extension data: [0xAA, 0xBB, 0xCC]
              15      00                  Padding byte (0x00)
```

### Example 2: Nested TLV Container
Consider a parent TLV object `Group` containing nested TLVs:
* Parent Tag: `'GRP_'` (`0x5F505247`)
* Parent Fixed Struct: 4 bytes (e.g., a single ID field `group_id = 0x99`).
* Extension: `TlvData` containing two nested child TLVs (each child is a `Foo`
  with 0-word payload, tag `'FOO_'`, `word_len = 0`).

#### Byte Layout:
```hexdump
Address/Word  Offset  Byte Values         Description
--------------------------------------------------------------------------------
Word 0        00..03  47 52 50 5F         Parent Tag: 'GRP_'
Word 1        04..05  05 00               Parent Word Length: 5 (20 bytes payload)
              06      00                  Parent Reserved: 0
              07      00                  Parent Flags: padding_bytes = 0
Word 2        08..11  99 00 00 00         Parent.group_id: 0x99
Word 3        12..15  46 4F 4F 5F         Child 1 Tag: 'FOO_'
Word 4        16..17  00 00               Child 1 Word Length: 0
              18      00                  Child 1 Reserved: 0
              19      00                  Child 1 Flags: padding_bytes = 0
Word 5        20..23  46 4F 4F 5F         Child 2 Tag: 'FOO_'
Word 6        24..25  00 00               Child 2 Word Length: 0
              26      00                  Child 2 Reserved: 0
              27      00                  Child 2 Flags: padding_bytes = 0
```
