# Protobuf-to-TLV Integration & Code Generation

This document describes how the TLV framework integrates with Protocol Buffers
(Protobuf) to enable schema authoring, code generation, and host-to-embedded
serialization.

---

## Architectural Role

While the embedded system uses highly optimized, zero-copy Rust structures at
runtime, authoring schemas directly in Rust can be tedious and error-prone.
Furthermore, host-side tools (written in Python, Go, C++, etc.) need a unified,
standard way to construct and serialize these messages.

The TLV framework solves this by utilizing Protobuf as a schema definition
language. The schema compiles into static Rust structures for the embedded
system, while host-side tools serialize standard Protobuf messages into the
aligned binary TLV format using reflection:

```text
                 [ Protobuf Schema (.proto) ]
                    /                  \
                   /                    \
                  v                      \ (descriptor set)
          [ ":codegen" ]                  v
                |                  [ ":proto_conv" ] <--- [ Protobuf Bytes ]
    (generates) |                        |
                v                        |
        [ Generated Rust ]               |
                |                        |
     (compiled) |                        | (proto_to_tlv)
                v                        v
       [ Zero-Copy Structs ]     [ Packed TLV Bytes ]
                \                      /
                 \                    / (communications)
                  v                  v
                +----------------------+
                |    Embedded Side     |
                | [Zero-Copy Overlay]  |
                +----------------------+
```

---

## Custom Options (`options.proto`)

The framework extends standard Protobuf descriptors with custom options defined
in [options.proto](options.proto). These options direct the code generator and the runtime serialization converter.

### 1. Message Options

* **`tlv_fourcc` (string):** Assigns a 4-character ASCII tag (FourCC) to the
  message. Any message with this option is compiled into a top-level TLV record
  type implementing `TlvObject`.
* **`bit_packed` (string):** Specifies the backing primitive integer type
  (`"u8"`, `"u16"`, or `"u32"`) for a bitfield struct. When present, the
  message is generated as a packed bitfield rather than a standard TLV.

### 2. Field Options

* **`offset` (uint32):** Specifies the byte offset of the field within the fixed
  struct of the TLV record.
  * Fields with an `offset` are compiled **inline** into the fixed struct.
  * Offsets must match the natural alignment of the field's backing Rust type
    (e.g., a `u32` field must reside at an offset divisible by 4).
* **`type` (string):** Overrides the generated Rust type. This is typically
  used to pack fields into smaller primitive integers (e.g., packing a Protobuf
  `uint32` into a Rust `u8` or `u16`) or to represent fixed-size arrays (e.g.,
  `"[u8; 16]"` for strings or `"[u32; 4]"` for UUIDs).
* **`bit_range` (string):** Specifies the bit range of a field in a bit-packed
  message using Verilog notation (e.g., `"0"` for a single bit, or `"7:3"` for
  a multi-bit range).

### 3. Enum Options

* **`raw_type` (string):** Specifies the backing primitive integer type for an
  enum (e.g., `"u8"`, `"u16"`, `"u32"`, `"i32"`).
  * Enums with this option are generated as type-safe **open enums** in Rust,
    which wrap the raw integer to prevent undefined behavior when casting
    arbitrary/invalid bytes from the wire.

---

## Layout Mapping Rules

A Protobuf message annotated for TLV is split into a **Fixed Struct** and a
**Variable-Length Extension**:

### The Fixed Struct (Inline Fields)
* Every field in the Protobuf message annotated with a `[(openprot.tlv.offset)]`
  is packed directly into the fixed struct at that byte offset.
* The total size of the fixed struct is padded to a multiple of 4 bytes.
* Nested messages can be embedded inline in the fixed struct if their type is
  a bitfield message (annotated with `bit_packed`) or a plain struct without a
  `tlv_fourcc`.

### The Variable-Length Extension (Nested TLVs)
* Any field **without** a `[(openprot.tlv.offset)]` is excluded from the fixed
  struct.
* These fields are automatically serialized as **nested TLV records** inside the
  parent TLV's variable-length extension.
* This applies to:
  * `repeated` fields of other TLV messages (serialized as a sequence of nested
    records).
  * Singular fields of other TLV messages (serialized as a single nested
    record).
  * `oneof` unions of TLV messages (serialized as a single nested record representing
    the active variant).

---

## Code Generation

The code generator (`tlv_codegen`) processes compiled Protobuf descriptor sets
(`FileDescriptorSet`) and outputs a single Rust module containing:
1. Standard zero-copy structs implementing `TlvObject` (for messages with
   `tlv_fourcc`).
2. Plain zero-copy helper structs (for nested inline messages).
3. Bitfield structs using `bitfield_struct::bitfield` (for messages with
   `bit_packed`).
4. Open enum wrappers (for enums with `raw_type`).

All generated structs automatically derive the necessary `zerocopy` traits
(`FromBytes`, `IntoBytes`, `Immutable`, `KnownLayout`).

---

## Bazel Integration (`tlv_codegen` macro)

The TLV framework provides a custom Bazel macro, `tlv_codegen` (defined in
[rules.bzl](rules.bzl)), to automate the code generation and compilation
pipeline. It compiles a `proto_library` directly into a first-class Rust
library (`rust_library`).

### Usage

To generate a Rust library from a `proto_library`, load the macro in your
`BUILD.bazel` file:

```bazel
load("//contrib/tlv:rules.bzl", "tlv_codegen")

proto_library(
    name = "soc_proto",
    srcs = ["soc.proto"],
    deps = ["//contrib/tlv:options_proto"],
)

tlv_codegen(
    name = "soc_tlv",
    proto = ":soc_proto",
    src = "soc_tlv.rs", # Recommended: checked-in source
)
```

### Golden File & IDE Integration Pattern

The `tlv_codegen` macro supports a highly developer-friendly "golden file"
pattern when the optional `src` attribute is specified:

1. **IDE Friendliness:** By specifying a checked-in file (`src = "soc_tlv.rs"`),
   the compiler and IDE tools (like `rust-analyzer`) can index the generated
   code directly inside the source tree, providing full autocomplete and
   go-to-definition support.
2. **Build-Time Verification:** Bazel automatically registers a verification
   action that compares the checked-in `src` file against a freshly generated
   one at build-time. If the checked-in file is stale (e.g., because the `.proto`
   file was modified), the build fails with a clear error.
3. **Automated Updates:** If the build fails due to a stale checked-in file, a
   companion binary target named `<name>_update` is automatically defined.
   Executing this target will automatically overwrite the checked-in file with the
   latest generated code:
   ```bash
   bazel run //path/to/package:soc_tlv_update
   ```

---

## Serialization Pipeline (`proto_conv`)

The `proto_conv` module provides the host-side converter that packs standard
serialized Protobuf bytes into the aligned binary TLV format.

### Key APIs

```rust
// Encodes raw serialized Protobuf bytes into a packed, 32-bit aligned TLV buffer.
pub fn proto_to_tlv(
    desc_set: &FileDescriptorSet,
    message_name: &str,
    proto_bytes: &[u8],
) -> Result<Vec<u32>, ProtoConvError>;

// Helper that serializes a Rust Protobuf struct and encodes it to TLV.
pub fn message_to_tlv<M: protobuf::Message>(
    info: &DescriptorInfo,
    message: &M,
) -> Result<Vec<u32>, ProtoConvError>;
```

### Validation Performed During Serialization
The converter performs rigorous checks to ensure the Protobuf data fits the
static constraints of the target Rust structures:
* **Range Checks:** Verifies that integer values fit within their overridden
  bit-widths (e.g., a value in a `bit_range` field or a field overridden with `u8`).
* **Length Checks:** Verifies that string or byte fields overridden with fixed-size
  arrays (like `[u8; 16]`) do not exceed their allocated size.
* **Alignment Checks:** Verifies that all field offsets are correctly aligned.

---

## Comprehensive Example

### 1. Protobuf Definition
```protobuf
syntax = "proto3";
import "contrib/tlv/options.proto";

enum SystemState {
  option (openprot.tlv.raw_type) = "u8";
  SYSTEM_IDLE = 0;
  SYSTEM_ACTIVE = 1;
}

message Features {
  option (openprot.tlv.bit_packed) = "u8";
  bool enable_dma = 1 [(openprot.tlv.bit_range) = "0"];
  uint32 speed_grade = 2 [(openprot.tlv.bit_range) = "3:1"];
}

message SubComponent {
  option (openprot.tlv.tlv_fourcc) = "SUB_";
  uint32 id = 1 [(openprot.tlv.offset) = 0];
}

message Device {
  option (openprot.tlv.tlv_fourcc) = "DEV_";

  uint32 device_id = 1 [(openprot.tlv.offset) = 0];
  SystemState state = 2 [(openprot.tlv.offset) = 4];
  Features features = 3 [(openprot.tlv.offset) = 5];

  // Nested TLV (no offset)
  repeated SubComponent components = 4;
}
```

### 2. Generated Rust Layout
The generator compiles the above definition into the following Rust code:

```rust
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(transparent)]
pub struct SystemState(pub u8);
impl SystemState {
    pub const IDLE: Self = Self(0);
    pub const ACTIVE: Self = Self(1);
}
impl ::core::fmt::Debug for SystemState {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        match *self {
            Self::IDLE => write!(f, "IDLE"),
            Self::ACTIVE => write!(f, "ACTIVE"),
            other => write!(f, "{}({})", stringify!(SystemState), other.0),
        }
    }
}

#[bitfield(u8)]
#[derive(PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct Features {
    #[bits(1)]
    pub enable_dma: bool,
    #[bits(3)]
    pub speed_grade: u8,
    #[bits(4)]
    __: (),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct SubComponent {
    pub id: u32,
}
const _: () = {
    assert!(::core::mem::offset_of!(SubComponent, id) == 0usize);
    assert!(::core::mem::align_of::<SubComponent>() <= 4);
    assert!(::core::mem::size_of::<SubComponent>() == 4usize);
};
impl ::mutask_tlv::TlvObject for SubComponent {
    type Extension = [u8];
    const TAG: u32 = u32::from_le_bytes(*b"SUB_");
    fn make_ext<'a>(header: &::mutask_tlv::TlvHeader, extra: &'a [u32]) -> &'a Self::Extension {
        ::mutask_tlv::unpad(header, extra)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct Device {
    pub device_id: u32,
    pub state: SystemState,
    pub features: Features,
    pub __pad0: [u8; 2usize],
}
const _: () = {
    assert!(::core::mem::offset_of!(Device, device_id) == 0usize);
    assert!(::core::mem::offset_of!(Device, state) == 4usize);
    assert!(::core::mem::offset_of!(Device, features) == 5usize);
    assert!(::core::mem::align_of::<Device>() <= 4);
    assert!(::core::mem::size_of::<Device>() == 8usize);
};
impl ::mutask_tlv::TlvObject for Device {
    type Extension = ::mutask_tlv::TlvData;
    const TAG: u32 = u32::from_le_bytes(*b"DEV_");
    fn make_ext<'a>(_header: &::mutask_tlv::TlvHeader, extra: &'a [u32]) -> &'a Self::Extension {
        ::mutask_tlv::TlvData::overlay(extra)
    }
}
pub trait DeviceExt<'a> {
    fn components(&self) -> ::mutask_tlv::TlvIterator<'a, SubComponent>;
}
impl<'a> DeviceExt<'a> for ::mutask_tlv::TlvItem<'a, Device> {
    fn components(&self) -> ::mutask_tlv::TlvIterator<'a, SubComponent> {
        ::mutask_tlv::TlvQuery::ext(self).iter::<SubComponent>()
    }
}
```

## Real-World Examples in the Repository

For complete, working examples of Protobuf definitions, generated Rust code,
and TLV byte generation, refer to the files checked into the repository:

* **System-on-Chip (SoC) Schema:**
  * Protobuf definition: [test/soc.proto](test/soc.proto)
  * Generated Rust code: [test/soc_tlv.rs](test/soc_tlv.rs)
  * Bazel target: `//contrib/tlv/test:soc_tlv`
* **TLV Byte Generation & Serialization:**
  * Serialization tests: [proto_conv.rs](proto_conv.rs) (see the test function
    `test_proto_to_tlv_system_hierarchy`)
  * This test demonstrates how to construct the Protobuf message structures
    and invoke `message_to_tlv` to generate the aligned, packed binary TLV
    words.
