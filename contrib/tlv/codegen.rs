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

use mutask_proto_reflect::TypeExt;
use mutask_tlv_proto_meta::BackingType;
use mutask_tlv_proto_meta::DescriptorProtoTlvExt;
use mutask_tlv_proto_meta::EnumDescriptorProtoTlvExt;
use mutask_tlv_proto_meta::FieldDescriptorProtoTlvExt;
use mutask_tlv_proto_meta::FieldLayout;
use mutask_tlv_proto_meta::NameStrExt;
use mutask_tlv_proto_meta::PackedPrimitiveType;
use mutask_tlv_proto_meta::PackedType;
use mutask_tlv_proto_meta::TlvLayout;
use mutask_tlv_proto_meta::find_enum_descriptor;
use mutask_tlv_proto_meta::find_message_descriptor;
use mutask_tlv_proto_meta::get_rust_struct_name;
use proc_macro2::Ident;
use proc_macro2::Literal;
use proc_macro2::Span;
use proc_macro2::TokenStream;
use protobuf::Parse;
use std::collections::HashMap;

use anyhow::Context;
use anyhow::Result;

// Re-export descriptor views
use descriptor_rust_proto::DescriptorProtoView;
use descriptor_rust_proto::FileDescriptorSet;

use argh::FromArgs;

#[derive(FromArgs)]
/// Protobuf-to-TLV code generator
struct Args {
    #[argh(option)]
    /// paths to descriptor sets
    descriptor_set: Vec<std::path::PathBuf>,

    #[argh(option)]
    /// paths to direct proto files (only emit code for types defined in these files)
    direct_proto: Vec<std::path::PathBuf>,

    #[argh(option)]
    /// path to direct descriptor set (only emit code for types in this descriptor set)
    direct_descriptor_set: Option<std::path::PathBuf>,

    #[argh(switch)]
    /// emit code for all files in descriptor set (disables direct file filtering)
    all_files: bool,

    #[argh(option)]
    /// rust crates to import (e.g. crypto_tlv)
    import_crate: Vec<String>,

    #[argh(option)]
    /// path to the output Rust file
    output: std::path::PathBuf,

    #[argh(option)]
    /// optional label of the diff test target
    test_label: Option<String>,
}

fn main() -> Result<()> {
    let args: Args = argh::from_env();

    if args.descriptor_set.is_empty() {
        anyhow::bail!("Missing --descriptor-set argument");
    }

    let mut desc_set = FileDescriptorSet::new();
    for path in &args.descriptor_set {
        let bytes = std::fs::read(path)
            .with_context(|| format!("Failed to read descriptor set from {}", path.display()))?;
        let part = FileDescriptorSet::parse(&bytes).with_context(|| {
            format!("Failed to parse FileDescriptorSet from {}", path.display())
        })?;
        desc_set
            .file_mut()
            .extend(part.file().into_iter().map(|f| f.to_owned()));
    }

    let mut direct_desc_names = std::collections::HashSet::new();
    if let Some(direct_ds_path) = &args.direct_descriptor_set {
        let bytes = std::fs::read(direct_ds_path).with_context(|| {
            format!(
                "Failed to read direct descriptor set from {}",
                direct_ds_path.display()
            )
        })?;
        let direct_set = FileDescriptorSet::parse(&bytes).with_context(|| {
            format!(
                "Failed to parse direct FileDescriptorSet from {}",
                direct_ds_path.display()
            )
        })?;
        for file in direct_set.file() {
            if let Ok(name) = file.name().to_str() {
                direct_desc_names.insert(name.to_string());
            }
        }
    }

    let target_files: Vec<_> = user_files(&desc_set)
        .filter(|f| {
            let file_name = f.name().to_str().unwrap_or("");
            is_direct_file(
                file_name,
                &args.direct_proto,
                &direct_desc_names,
                args.all_files,
            )
        })
        .collect();

    let crates_to_import: std::collections::BTreeSet<_> =
        args.import_crate.iter().cloned().collect();

    let mut out = String::new();
    out.push_str("// Copyright 2026 Google LLC\n");
    out.push_str("//\n");
    out.push_str("// Licensed under the Apache License, Version 2.0 (the \"License\");\n");
    out.push_str("// you may not use this file except in compliance with the License.\n");
    out.push_str("// You may obtain a copy of the License at\n");
    out.push_str("//\n");
    out.push_str("//     http://www.apache.org/licenses/LICENSE-2.0\n");
    out.push_str("//\n");
    out.push_str("// Unless required by applicable law or agreed to in writing, software\n");
    out.push_str("// distributed under the License is distributed on an \"AS IS\" BASIS,\n");
    out.push_str("// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n");
    out.push_str("// See the License for the specific language governing permissions and\n");
    out.push_str("// limitations under the License.\n\n");
    out.push_str("// Automatically generated by tlv_codegen. DO NOT EDIT.\n");
    if let Some(label) = &args.test_label {
        out.push_str(&format!(
            "// To regenerate, run:\n//     bazel run {label}\n",
        ));
    }
    out.push('\n');
    out.push_str("#![no_std]\n");
    out.push_str("#![allow(non_camel_case_types)]\n");
    out.push_str("#![allow(non_snake_case)]\n");
    out.push_str("#![allow(unused_imports)]\n");
    out.push_str("#![allow(dead_code)]\n\n");
    out.push_str("use bitfield_struct::bitfield;\n");
    out.push_str("use mutask_tlv::TlvFlags;\n");
    out.push_str("use mutask_tlv::TlvHeader;\n");
    out.push_str("use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};\n");
    for crate_name in &crates_to_import {
        out.push_str(&format!("pub use {}::*;\n", crate_name));
    }
    out.push('\n');

    // Traverse direct target files and collect all messages with their full package-relative names
    let mut all_messages = Vec::new();
    for file in &target_files {
        for msg in file.message_type() {
            collect_messages_nested(msg, "", &mut all_messages);
        }
    }

    // Traverse direct target files and collect all enums with their full package-relative names
    let mut all_enums = Vec::new();
    for file in &target_files {
        let package = file.package().to_str().unwrap_or("");
        for en in file.enum_type() {
            if en.raw_type().is_some() {
                let full_name = if package.is_empty() {
                    en.name().to_str().unwrap_or("").to_string()
                } else {
                    format!("{}.{}", package, en.name().to_str().unwrap_or(""))
                };
                all_enums.push((en, full_name));
            }
        }
        for msg in file.message_type() {
            collect_enums_nested(package, msg, &mut all_enums);
        }
    }

    // Generate code for all enums using the open-enum pattern
    for (en, full_name) in &all_enums {
        let tokens = generate_open_enum(*en, full_name, &desc_set);
        out.push_str(&tokens.to_string());
        out.push_str("\n\n");
    }

    // Generate code for all messages that have TLV or BitPacked layouts
    for (msg, full_type_name) in all_messages {
        let has_fourcc = msg.tlv_fourcc().is_some();
        let has_bit_packed = msg.bit_packed()?.is_some();

        if has_fourcc || has_bit_packed {
            let layout = msg.tlv_layout_with_name(&full_type_name, &desc_set)?;
            let tokens = if has_bit_packed {
                generate_bit_packed(msg, &full_type_name, layout, &desc_set)?
            } else {
                generate_standard_tlv(msg, &full_type_name, layout, &desc_set)?
            };
            out.push_str(&tokens.to_string());
            out.push_str("\n\n");
        } else {
            // Also generate plain structs for any standard nested messages used inline
            // that don't have their own tlv_fourcc.
            if let Ok(layout @ TlvLayout::Standard { .. }) =
                msg.tlv_layout_with_name(&full_type_name, &desc_set)
            {
                let tokens = generate_plain_struct(msg, &full_type_name, layout, &desc_set)?;
                out.push_str(&tokens.to_string());
                out.push_str("\n\n");
            }
        }
    }

    let formatted = format_code(&out).context("Failed to format generated code")?;

    std::fs::write(&args.output, formatted).with_context(|| {
        format!(
            "Failed to write generated code to {}",
            args.output.display()
        )
    })?;
    Ok(())
}

fn format_code(code: &str) -> Result<String> {
    use std::io::Write;
    use std::process::Command;
    use std::process::Stdio;

    let rustfmt_path = std::env::var("RUSTFMT").unwrap_or_else(|_| "rustfmt".to_string());
    let mut child = Command::new(rustfmt_path)
        .args(["--edition", "2024", "--config-path", "/dev/null"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Failed to spawn rustfmt process")?;

    child
        .stdin
        .take()
        .context("Failed to open stdin for rustfmt")?
        .write_all(code.as_bytes())?;

    let output = child.wait_with_output()?;
    if !output.status.success() {
        anyhow::bail!(
            "rustfmt failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8(output.stdout)?)
}

fn collect_messages_nested<'a>(
    msg: DescriptorProtoView<'a>,
    parent_name: &str,
    messages: &mut Vec<(DescriptorProtoView<'a>, String)>,
) {
    let full_name = if parent_name.is_empty() {
        msg.name_str().to_string()
    } else {
        format!("{}.{}", parent_name, msg.name_str())
    };
    messages.push((msg, full_name.clone()));
    for nested in msg.nested_type() {
        collect_messages_nested(nested, &full_name, messages);
    }
}

fn collect_enums_nested<'a>(
    parent_path: &str,
    msg: DescriptorProtoView<'a>,
    out: &mut Vec<(descriptor_rust_proto::EnumDescriptorProtoView<'a>, String)>,
) {
    let msg_name = msg.name_str();
    let current_path = if parent_path.is_empty() {
        msg_name.to_string()
    } else {
        format!("{}.{}", parent_path, msg_name)
    };

    for en in msg.enum_type() {
        if en.raw_type().is_some() {
            let full_name = format!("{}.{}", current_path, en.name().to_str().unwrap_or(""));
            out.push((en, full_name));
        }
    }

    for nested in msg.nested_type() {
        collect_enums_nested(&current_path, nested, out);
    }
}

fn find_common_prefix_to_strip(variant_names: &[String]) -> Option<String> {
    if variant_names.len() <= 1 {
        return None;
    }

    // 1. Find the longest common prefix
    let mut common = variant_names[0].clone();
    for name in variant_names.iter().skip(1) {
        let mut len = 0;
        for (c1, c2) in common.chars().zip(name.chars()) {
            if c1 == c2 {
                len += c1.len_utf8();
            } else {
                break;
            }
        }
        common.truncate(len);
    }

    // 2. Find the last underscore in the common prefix
    let last_under = common.rfind('_')?;
    let prefix = &common[..=last_under]; // Includes the '_'

    if prefix.is_empty() {
        return None;
    }

    // 3. Validate that all stripped names are valid Rust identifiers
    for name in variant_names {
        let stripped = name.strip_prefix(prefix)?;
        if stripped.is_empty() {
            return None;
        }
        // Rust identifiers cannot start with a digit
        if stripped.chars().next().unwrap().is_ascii_digit() {
            return None;
        }
    }

    Some(prefix.to_string())
}

fn generate_open_enum(
    en: descriptor_rust_proto::EnumDescriptorProtoView<'_>,
    full_name: &str,
    desc_set: &FileDescriptorSet,
) -> TokenStream {
    let rust_name = get_rust_struct_name(full_name, desc_set);
    let ident = get_ident(&rust_name);

    let backing_type_str = en.raw_type().unwrap_or_else(|| "i32".to_string());
    let backing_type: TokenStream = backing_type_str.parse().unwrap();

    let mut variant_names = Vec::new();
    for val in en.value() {
        variant_names.push(val.name().to_str().unwrap_or("").to_string());
    }

    let prefix_to_strip = find_common_prefix_to_strip(&variant_names);

    let mut variants = Vec::new();
    let mut debug_matches = Vec::new();
    let mut seen_values = std::collections::HashSet::new();
    for val in en.value() {
        let val_name_raw = val.name().to_str().unwrap_or("");
        let val_name = if let Some(prefix) = &prefix_to_strip {
            val_name_raw.strip_prefix(prefix).unwrap_or(val_name_raw)
        } else {
            val_name_raw
        };
        let val_number = val.number();
        let val_lit = proc_macro2::Literal::i32_unsuffixed(val_number);
        let variant_ident = get_ident(val_name);

        variants.push(quote::quote! {
            pub const #variant_ident: Self = Self(#val_lit);
        });

        if seen_values.insert(val_number) {
            let val_name_str = variant_ident.to_string();
            debug_matches.push(quote::quote! {
                Self::#variant_ident => write!(f, #val_name_str),
            });
        }
    }

    quote::quote! {
        #[derive(Clone, Copy, PartialEq, Eq, Hash, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
        #[repr(transparent)]
        pub struct #ident(pub #backing_type);

        impl #ident {
            #(#variants)*
        }

        impl ::core::fmt::Debug for #ident {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                match *self {
                    #(#debug_matches)*
                    other => write!(f, "{}({})", stringify!(#ident), other.0),
                }
            }
        }
    }
}

fn get_ident(name: &str) -> Ident {
    const KEYWORDS: &[&str] = &[
        "as", "break", "const", "continue", "crate", "else", "enum", "extern", "false", "fn",
        "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref",
        "return", "self", "Self", "static", "struct", "super", "trait", "true", "type", "unsafe",
        "use", "where", "while", "async", "await", "dyn",
    ];
    if KEYWORDS.contains(&name) {
        Ident::new_raw(name, Span::call_site())
    } else {
        Ident::new(name, Span::call_site())
    }
}

fn get_bitfield_type(
    bit_len: usize,
    proto_type: descriptor_rust_proto::field_descriptor_proto::Type,
) -> &'static str {
    let is_signed = proto_type
        .primitive_info()
        .is_some_and(|info| info.is_signed);
    if bit_len == 1 {
        "bool"
    } else if bit_len <= 8 {
        if is_signed { "i8" } else { "u8" }
    } else if bit_len <= 16 {
        if is_signed { "i16" } else { "u16" }
    } else if bit_len <= 32 {
        if is_signed { "i32" } else { "u32" }
    } else {
        if is_signed { "i64" } else { "u64" }
    }
}

fn generate_bit_packed(
    msg: DescriptorProtoView<'_>,
    full_type_name: &str,
    layout: TlvLayout,
    desc_set: &FileDescriptorSet,
) -> Result<TokenStream> {
    let msg_name = get_rust_struct_name(full_type_name, desc_set);
    let msg_ident = get_ident(&msg_name);

    let (fields, backing) = match layout {
        TlvLayout::BitPacked { fields, backing } => (fields, backing),
        _ => anyhow::bail!("Expected BitPacked layout"),
    };

    let backing_ident = match backing {
        BackingType::U8 => get_ident("u8"),
        BackingType::U16 => get_ident("u16"),
        BackingType::U32 => get_ident("u32"),
    };

    let mut field_tokens = Vec::new();
    let mut sorted_fields = Vec::new();
    for field in msg.field() {
        let num = field.number() as u32;
        if let Some(packed_field) = fields.get(&num) {
            sorted_fields.push((field, packed_field));
        }
    }
    sorted_fields.sort_by_key(|f| f.1.bit_offset);

    let mut current_bit = 0;
    for (field, packed_field) in sorted_fields {
        let bit_offset = packed_field.bit_offset;
        let bit_len = packed_field.bit_len;

        if bit_offset > current_bit {
            let gap = bit_offset - current_bit;
            let gap_lit = Literal::usize_unsuffixed(gap);
            field_tokens.push(quote::quote! {
                #[bits(#gap_lit)]
                __ : (),
            });
        }

        let field_ident = get_ident(field.name_str());
        let rust_type_str = get_bitfield_type(bit_len, field.r#type());
        let rust_type: TokenStream = rust_type_str.parse().unwrap();
        let bit_len_lit = Literal::usize_unsuffixed(bit_len);

        field_tokens.push(quote::quote! {
            #[bits(#bit_len_lit)]
            pub #field_ident: #rust_type,
        });

        current_bit = bit_offset + bit_len;
    }

    let total_bits = backing.bits();
    if total_bits > current_bit {
        let gap = total_bits - current_bit;
        let gap_lit = Literal::usize_unsuffixed(gap);
        field_tokens.push(quote::quote! {
            #[bits(#gap_lit)]
            __ : (),
        });
    }

    Ok(quote::quote! {
        #[bitfield(#backing_ident)]
        #[derive(PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
        pub struct #msg_ident {
            #(#field_tokens)*
        }
    })
}

fn generate_const_assertions(
    msg_ident: &Ident,
    fields: &HashMap<u32, FieldLayout>,
    fixed_struct_size: usize,
    msg: DescriptorProtoView<'_>,
) -> TokenStream {
    let mut field_assertions = Vec::new();
    for field in msg.field() {
        let num = field.number() as u32;
        if let Some(FieldLayout::Fixed { offset, .. }) = fields.get(&num) {
            let field_ident = get_ident(field.name_str());
            field_assertions.push(quote::quote! {
                assert!(::core::mem::offset_of!(#msg_ident, #field_ident) == #offset);
            });
        }
    }

    quote::quote! {
        const _: () = {
            #(#field_assertions)*
            assert!(::core::mem::align_of::<#msg_ident>() <= 4);
            assert!(::core::mem::size_of::<#msg_ident>() == #fixed_struct_size);
        };
    }
}

fn generate_standard_tlv(
    msg: DescriptorProtoView<'_>,
    full_type_name: &str,
    layout: TlvLayout,
    desc_set: &FileDescriptorSet,
) -> Result<TokenStream> {
    let msg_name = get_rust_struct_name(full_type_name, desc_set);
    let msg_ident = get_ident(&msg_name);

    let (fields, fixed_struct_size) = match layout {
        TlvLayout::Standard {
            fields,
            fixed_struct_size,
        } => (fields, fixed_struct_size),
        _ => anyhow::bail!("Expected Standard layout"),
    };

    let has_dynamic_tlvs = fields
        .values()
        .any(|f| matches!(f, FieldLayout::Tlv { .. }));

    let ext_type = if has_dynamic_tlvs {
        quote::quote! { ::mutask_tlv::TlvData }
    } else {
        quote::quote! { [u8] }
    };

    let make_ext_body = if has_dynamic_tlvs {
        quote::quote! { ::mutask_tlv::TlvData::overlay(extra) }
    } else {
        quote::quote! { ::mutask_tlv::unpad(header, extra) }
    };

    let header_arg = if has_dynamic_tlvs {
        quote::quote! { _header }
    } else {
        quote::quote! { header }
    };

    let fourcc = msg.tlv_fourcc().unwrap();
    let fourcc_lit = Literal::byte_string(&fourcc);

    let field_tokens = generate_struct_fields(msg, &fields, fixed_struct_size, desc_set)?;

    let (mut signatures, mut accessors) = generate_sub_tlv_accessors(msg, &fields, desc_set)?;
    let (enum_decls, oneof_sigs, oneof_accs) = generate_oneofs(msg, &msg_name, desc_set)?;
    signatures.extend(oneof_sigs);
    accessors.extend(oneof_accs);

    let accessors_impl = if !accessors.is_empty() {
        let trait_ident = get_ident(&format!("{}Ext", msg_name));
        quote::quote! {
            pub trait #trait_ident<'a> {
                #(#signatures)*
            }

            impl<'a> #trait_ident<'a> for ::mutask_tlv::TlvItem<'a, #msg_ident> {
                #(#accessors)*
            }
        }
    } else {
        quote::quote! {}
    };

    let mut visited = std::collections::HashSet::new();
    let derives = if has_floats(msg, desc_set, &mut visited) {
        quote::quote! { #[derive(Debug, Clone, Copy, PartialEq, FromBytes, IntoBytes, Immutable, KnownLayout)] }
    } else {
        quote::quote! { #[derive(Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)] }
    };

    let const_assertions = generate_const_assertions(&msg_ident, &fields, fixed_struct_size, msg);

    Ok(quote::quote! {
        #derives
        #[repr(C)]
        pub struct #msg_ident {
            #(#field_tokens)*
        }

        #const_assertions

        impl ::core::default::Default for #msg_ident {
            fn default() -> Self {
                ::zerocopy::FromZeros::new_zeroed()
            }
        }

        impl ::mutask_tlv::TlvObject for #msg_ident {
            type Extension = #ext_type;
            const TAG: u32 = u32::from_le_bytes(*#fourcc_lit);
            fn make_ext<'a>(#header_arg: &::mutask_tlv::TlvHeader, extra: &'a [u32]) -> &'a Self::Extension {
                #make_ext_body
            }
        }

        #(#enum_decls)*

        #accessors_impl
    })
}

fn generate_sub_tlv_accessors(
    msg: DescriptorProtoView<'_>,
    fields: &HashMap<u32, FieldLayout>,
    desc_set: &FileDescriptorSet,
) -> Result<(Vec<TokenStream>, Vec<TokenStream>)> {
    use descriptor_rust_proto::field_descriptor_proto::Label;

    let mut signatures = Vec::new();
    let mut accessors = Vec::new();
    for field in msg.field() {
        let num = field.number() as u32;
        if let Some(layout) = fields.get(&num) {
            match layout {
                FieldLayout::Tlv { .. } => {
                    let field_ident = get_ident(field.name_str());

                    let type_name_raw = field.type_name().to_str().unwrap_or("");
                    let type_name = type_name_raw.strip_prefix('.').unwrap_or(type_name_raw);
                    let child_struct_name = get_rust_struct_name(type_name, desc_set);
                    let child_ident = get_ident(&child_struct_name);

                    let is_repeated = field.label() == Label::Repeated;

                    if is_repeated {
                        signatures.push(quote::quote! {
                            fn #field_ident(&self) -> ::mutask_tlv::TlvIterator<'a, #child_ident>;
                        });
                        accessors.push(quote::quote! {
                            fn #field_ident(&self) -> ::mutask_tlv::TlvIterator<'a, #child_ident> {
                                ::mutask_tlv::TlvQuery::ext(self).iter::<#child_ident>()
                            }
                        });
                    } else {
                        signatures.push(quote::quote! {
                            fn #field_ident(&self) -> Option<::mutask_tlv::TlvItem<'a, #child_ident>>;
                        });
                        accessors.push(quote::quote! {
                            fn #field_ident(&self) -> Option<::mutask_tlv::TlvItem<'a, #child_ident>> {
                                ::mutask_tlv::TlvQuery::ext(self).iter::<#child_ident>().next()
                            }
                        });
                    }
                }
                FieldLayout::ExtraData => {
                    let field_ident = get_ident(field.name_str());
                    let kind = field.r#type();
                    if kind == descriptor_rust_proto::field_descriptor_proto::Type::String {
                        signatures.push(quote::quote! {
                            fn #field_ident(&self) -> &'a ::bstr::BStr;
                        });
                        accessors.push(quote::quote! {
                            fn #field_ident(&self) -> &'a ::bstr::BStr {
                                use ::mutask_tlv::TlvQuery;
                                ::bstr::BStr::new(self.ext())
                            }
                        });
                    } else {
                        signatures.push(quote::quote! {
                            fn #field_ident(&self) -> &'a [u8];
                        });
                        accessors.push(quote::quote! {
                            fn #field_ident(&self) -> &'a [u8] {
                                use ::mutask_tlv::TlvQuery;
                                self.ext()
                            }
                        });
                    }
                }
                _ => {}
            }
        }
    }
    Ok((signatures, accessors))
}

fn generate_plain_struct(
    msg: DescriptorProtoView<'_>,
    full_type_name: &str,
    layout: TlvLayout,
    desc_set: &FileDescriptorSet,
) -> Result<TokenStream> {
    let msg_name = get_rust_struct_name(full_type_name, desc_set);
    let msg_ident = get_ident(&msg_name);

    let (fields, fixed_struct_size) = match layout {
        TlvLayout::Standard {
            fields,
            fixed_struct_size,
        } => (fields, fixed_struct_size),
        _ => anyhow::bail!("Expected Standard layout"),
    };

    let field_tokens = generate_struct_fields(msg, &fields, fixed_struct_size, desc_set)?;

    let mut visited = std::collections::HashSet::new();
    let derives = if has_floats(msg, desc_set, &mut visited) {
        quote::quote! { #[derive(Debug, Clone, Copy, PartialEq, FromBytes, IntoBytes, Immutable, KnownLayout)] }
    } else {
        quote::quote! { #[derive(Debug, Clone, Copy, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)] }
    };

    let const_assertions = generate_const_assertions(&msg_ident, &fields, fixed_struct_size, msg);

    Ok(quote::quote! {
        #derives
        #[repr(C)]
        pub struct #msg_ident {
            #(#field_tokens)*
        }

        #const_assertions

        impl ::core::default::Default for #msg_ident {
            fn default() -> Self {
                ::zerocopy::FromZeros::new_zeroed()
            }
        }
    })
}

fn to_aligned_rust_type(pt: &PackedType) -> String {
    match pt {
        PackedType::Primitive(prim) => match prim {
            PackedPrimitiveType::U64 => "::mutask_aligned::U64Align4".to_string(),
            PackedPrimitiveType::I64 => "::zerocopy::byteorder::native_endian::I64".to_string(),
            PackedPrimitiveType::F64 => "::zerocopy::byteorder::native_endian::F64".to_string(),
            _ => prim.to_string(),
        },
        PackedType::Array { elem, len } => {
            let elem_str = match elem {
                PackedPrimitiveType::U64 => "::mutask_aligned::U64Align4".to_string(),
                PackedPrimitiveType::I64 => "::zerocopy::byteorder::native_endian::I64".to_string(),
                PackedPrimitiveType::F64 => "::zerocopy::byteorder::native_endian::F64".to_string(),
                _ => elem.to_string(),
            };
            format!("[{}; {}]", elem_str, len)
        }
        PackedType::Struct { name, .. } => name.clone(),
    }
}

fn generate_struct_fields(
    msg: DescriptorProtoView<'_>,
    fields: &HashMap<u32, FieldLayout>,
    fixed_struct_size: usize,
    desc_set: &FileDescriptorSet,
) -> Result<Vec<TokenStream>> {
    let mut fixed_fields = Vec::new();
    for field in msg.field() {
        let num = field.number() as u32;
        if let Some(FieldLayout::Fixed {
            offset,
            packed_type,
        }) = fields.get(&num)
        {
            let rust_type_str =
                if field.r#type() == descriptor_rust_proto::field_descriptor_proto::Type::Enum {
                    let type_name_raw = field.type_name().to_str().unwrap_or("");
                    let type_name = type_name_raw.strip_prefix('.').unwrap_or(type_name_raw);

                    let has_raw_type = find_enum_descriptor(desc_set, type_name)
                        .and_then(|e| e.raw_type())
                        .is_some();

                    if has_raw_type && field.type_option().is_none() {
                        get_rust_struct_name(type_name, desc_set)
                    } else {
                        to_aligned_rust_type(packed_type)
                    }
                } else {
                    to_aligned_rust_type(packed_type)
                };

            fixed_fields.push((field, *offset, packed_type.size(), rust_type_str));
        }
    }
    fixed_fields.sort_by_key(|f| f.1);

    let mut field_tokens = Vec::new();
    let mut current_offset = 0;
    let mut pad_count = 0;
    for (field, offset, size, rust_type_str) in fixed_fields {
        if offset > current_offset {
            let gap = offset - current_offset;
            let pad_ident = get_ident(&format!("__pad{}", pad_count));
            field_tokens.push(quote::quote! {
                pub #pad_ident: [u8; #gap],
            });
            pad_count += 1;
        }

        let field_ident = get_ident(field.name_str());
        let rust_type: TokenStream = rust_type_str.parse().unwrap();

        field_tokens.push(quote::quote! {
            pub #field_ident: #rust_type,
        });

        current_offset = offset + size;
    }

    if fixed_struct_size > current_offset {
        let gap = fixed_struct_size - current_offset;
        let pad_ident = get_ident(&format!("__pad{}", pad_count));
        field_tokens.push(quote::quote! {
            pub #pad_ident: [u8; #gap],
        });
    }

    Ok(field_tokens)
}

fn has_floats<'a>(
    msg: descriptor_rust_proto::DescriptorProtoView<'a>,
    desc_set: &'a FileDescriptorSet,
    visited: &mut std::collections::HashSet<String>,
) -> bool {
    use descriptor_rust_proto::field_descriptor_proto::Type;

    let msg_name = msg.name_str().to_string();
    if !visited.insert(msg_name) {
        return false;
    }

    for field in msg.field() {
        if field.r#type() == Type::Float || field.r#type() == Type::Double {
            return true;
        }

        if field.r#type() == Type::Message || field.r#type() == Type::Group {
            let type_name_raw = field.type_name().to_str().unwrap_or("");
            let type_name = type_name_raw.strip_prefix('.').unwrap_or(type_name_raw);
            if let Some(child_desc) = find_message_descriptor(desc_set, type_name) {
                if has_floats(child_desc, desc_set, visited) {
                    return true;
                }
            }
        }
    }

    false
}

fn to_camel_case(s: &str) -> String {
    s.split('_')
        .map(|word| {
            let mut c = word.chars();
            match c.next() {
                None => String::new(),
                Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
            }
        })
        .collect::<String>()
}

fn generate_oneofs(
    msg: DescriptorProtoView<'_>,
    msg_name: &str,
    desc_set: &FileDescriptorSet,
) -> Result<(Vec<TokenStream>, Vec<TokenStream>, Vec<TokenStream>)> {
    let mut enum_decls = Vec::new();
    let mut signatures = Vec::new();
    let mut accessors = Vec::new();

    for (index, oneof_decl) in msg.oneof_decl().iter().enumerate() {
        let oneof_name = oneof_decl.name().to_str().unwrap_or("");
        if oneof_name.is_empty() {
            continue;
        }

        let mut oneof_fields = Vec::new();
        for field in msg.field() {
            if field.has_oneof_index() && field.oneof_index() == index as i32 {
                oneof_fields.push(field);
            }
        }

        if oneof_fields.is_empty() {
            continue;
        }

        let oneof_name_camel = to_camel_case(oneof_name);
        let enum_name = format!("{}{}", msg_name, oneof_name_camel);
        let enum_ident = get_ident(&enum_name);

        let mut variants = Vec::new();
        let mut checks = Vec::new();

        for field in &oneof_fields {
            let variant_name = to_camel_case(field.name_str());
            let variant_ident = get_ident(&variant_name);

            let type_name_raw = field.type_name().to_str().unwrap_or("");
            let type_name = type_name_raw.strip_prefix('.').unwrap_or(type_name_raw);
            let child_struct_name = get_rust_struct_name(type_name, desc_set);
            let child_ident = get_ident(&child_struct_name);

            variants.push(quote::quote! {
                #variant_ident(::mutask_tlv::TlvItem<'a, #child_ident>),
            });

            checks.push(quote::quote! {
                if let Some(val) = item.cast::<#child_ident>() {
                    return Some(#enum_ident::#variant_ident(val));
                }
            });
        }

        enum_decls.push(quote::quote! {
            pub enum #enum_ident<'a> {
                #(#variants)*
            }
        });

        let accessor_ident = get_ident(oneof_name);
        signatures.push(quote::quote! {
            fn #accessor_ident(&self) -> Option<#enum_ident<'a>>;
        });

        accessors.push(quote::quote! {
            fn #accessor_ident(&self) -> Option<#enum_ident<'a>> {
                use ::mutask_tlv::TlvQuery;
                for item in ::mutask_tlv::TlvQuery::ext(self).iter::<::mutask_tlv::TlvAny>() {
                    #(#checks)*
                }
                None
            }
        });
    }

    Ok((enum_decls, signatures, accessors))
}

/// Helper iterator filtering out built-in `google.protobuf` descriptor schema files.
fn user_files<'a>(
    desc_set: &'a FileDescriptorSet,
) -> impl Iterator<Item = descriptor_rust_proto::FileDescriptorProtoView<'a>> {
    desc_set.file().into_iter().filter(|f| {
        !f.package()
            .to_str()
            .unwrap_or("")
            .starts_with("google.protobuf")
    })
}

fn matches_path(full_path: &str, target: &str) -> bool {
    let full_path = full_path.trim();
    let target = target.trim();
    if full_path == target {
        return true;
    }
    if let Some(stripped) = full_path.strip_suffix(target) {
        if stripped.ends_with('/') || stripped.ends_with('\\') {
            return true;
        }
    }
    if let Some(stripped) = target.strip_suffix(full_path) {
        if stripped.ends_with('/') || stripped.ends_with('\\') {
            return true;
        }
    }
    false
}

fn is_direct_file(
    file_name: &str,
    direct_protos: &[std::path::PathBuf],
    direct_desc_names: &std::collections::HashSet<String>,
    all_files: bool,
) -> bool {
    if all_files {
        return true;
    }
    if direct_desc_names.contains(file_name) {
        return true;
    }
    for dp in direct_protos {
        let dp_str = dp.to_string_lossy();
        if matches_path(file_name, &dp_str) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matches_path() {
        assert!(matches_path(
            "path/to/my_message.proto",
            "external/repo+/path/to/my_message.proto"
        ));
        assert!(matches_path(
            "path/to/my_message.proto",
            "../repo+/path/to/my_message.proto"
        ));
        assert!(matches_path(
            "path/to/my_message.proto",
            "path/to/my_message.proto"
        ));
        assert!(matches_path("path/to/my_message.proto", "my_message.proto"));
        assert!(!matches_path("path/to/my_message.proto", "other.proto"));
        assert!(!matches_path(
            "path/to/not_my_message.proto",
            "my_message.proto"
        ));
    }

    #[test]
    fn test_is_direct_file() {
        let direct_protos = vec![std::path::PathBuf::from("path/to/my_message.proto")];
        let mut direct_desc = std::collections::HashSet::new();
        direct_desc.insert("desc_message.proto".to_string());

        // Matching direct_protos
        assert!(is_direct_file(
            "path/to/my_message.proto",
            &direct_protos,
            &direct_desc,
            false
        ));
        assert!(is_direct_file(
            "external/repo+/path/to/my_message.proto",
            &direct_protos,
            &direct_desc,
            false
        ));

        // Matching direct_desc_names
        assert!(is_direct_file(
            "desc_message.proto",
            &direct_protos,
            &direct_desc,
            false
        ));

        // Not matching
        assert!(!is_direct_file(
            "other.proto",
            &direct_protos,
            &direct_desc,
            false
        ));

        // Empty direct_protos and direct_desc_names with all_files = false (aggregating target)
        let empty_protos = vec![];
        let empty_desc = std::collections::HashSet::new();
        assert!(!is_direct_file(
            "path/to/my_message.proto",
            &empty_protos,
            &empty_desc,
            false
        ));

        // all_files = true overrides and matches everything
        assert!(is_direct_file(
            "path/to/my_message.proto",
            &empty_protos,
            &empty_desc,
            true
        ));
        assert!(is_direct_file(
            "other.proto",
            &empty_protos,
            &empty_desc,
            true
        ));
    }

    #[test]
    fn test_find_common_prefix_to_strip() {
        let cases = vec![
            (
                vec![
                    "EU_STATE_IDLE",
                    "EU_STATE_BUSY",
                    "EU_STATE_STALLED",
                    "EU_STATE_LARGE",
                ],
                Some("EU_STATE_"),
            ),
            (
                vec!["CPU_STATE_OFFLINE", "CPU_STATE_ACTIVE", "CPU_STATE_SLEEP"],
                Some("CPU_STATE_"),
            ),
            (
                vec!["EU_STATE_0", "EU_STATE_1"],
                None, // Stripping EU_STATE_ would leave "0", "1" which are invalid identifiers starting with a digit.
            ),
            (
                vec!["EU_STATE", "EU_STATE_BUSY"],
                Some("EU_"), // Stripping EU_ leaves STATE and STATE_BUSY (valid).
            ),
            (
                vec!["PREFIXA", "PREFIXB"],
                None, // No underscore in the common prefix "PREFIX".
            ),
            (
                vec!["A", "B", "C"],
                None, // No common prefix.
            ),
            (
                vec!["ONLY_ONE"],
                None, // Single element should not strip anything.
            ),
        ];

        for (input, expected) in cases {
            let string_input: Vec<String> = input.into_iter().map(|s| s.to_string()).collect();
            let result = find_common_prefix_to_strip(&string_input);
            assert_eq!(result.as_deref(), expected);
        }
    }
}
