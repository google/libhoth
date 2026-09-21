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

//! TLV inspection: a schema-free wire walker for raw structure inspection.

use anyhow::Result;
use anyhow::ensure;
use core::fmt;
use core::fmt::Write as _;
use mutask_tlv::TlvAny;
use mutask_tlv::TlvData;
use mutask_tlv::TlvHeader;
use mutask_tlv::word_size_of;
use zerocopy::IntoBytes;

/// Maximum number of payload bytes rendered as hex in a leaf node.
const PREVIEW_BYTES: usize = 32;

/// A node in the raw TLV container hierarchy.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RawNode {
    header: TlvHeader,
    byte_offset: usize,
    data_preview: Option<String>,
    children: Vec<RawNode>,
}

/// Formats a 32-bit tag as printable ASCII if possible, otherwise hex.
fn format_tag_fourcc(tag: u32) -> String {
    let b = tag.to_le_bytes();
    if b.iter().all(|&c| (0x20..=0x7e).contains(&c)) {
        let s = core::str::from_utf8(&b).expect("printable ASCII is valid UTF-8");
        format!("'{s}'")
    } else {
        format!("0x{:08X}", tag)
    }
}

/// Returns true if a header is well-formed on the wire: a non-zero tag with all
/// reserved bits clear.
fn is_plausible(header: &TlvHeader) -> bool {
    header.tag != 0 && header.reserved == 0 && header.flags.into_bits() >> 2 == 0
}

/// Renders up to [`PREVIEW_BYTES`] of unpadded payload as hex, or `None` if empty.
fn preview(header: &TlvHeader, payload: &[u32]) -> Option<String> {
    let bytes = payload.as_bytes();
    let bytes = bytes.get(..header.byte_len()).unwrap_or(bytes);
    if bytes.is_empty() {
        return None;
    }
    let mut hex = hex::encode(&bytes[..bytes.len().min(PREVIEW_BYTES)]);
    if bytes.len() > PREVIEW_BYTES {
        hex.push_str("...");
    }
    Some(hex)
}

/// Walks `words` as a sequence of TLV containers, stopping at the first one that
/// is truncated or implausible.
///
/// Returns the nodes parsed and the number of words they consumed; a payload is
/// only treated as nested TLV when its containers consume it exactly.
fn walk(words: &[u32], base_offset: usize) -> (Vec<RawNode>, usize) {
    let mut nodes = Vec::new();
    let mut consumed = 0;
    for item in TlvData::overlay(words).iter::<TlvAny>() {
        let header = item.container.header;
        if !is_plausible(&header) {
            break;
        }
        let byte_offset = base_offset + consumed * 4;
        let payload_offset = byte_offset + word_size_of::<TlvHeader>() * 4;
        let (children, nested_words) = walk(item.extra, payload_offset);
        let has_nested = !children.is_empty() && nested_words == item.extra.len();
        nodes.push(RawNode {
            byte_offset,
            data_preview: (!has_nested)
                .then(|| preview(&header, item.extra))
                .flatten(),
            children: if has_nested { children } else { Vec::new() },
            header,
        });
        consumed += item.container.as_words().len();
    }
    (nodes, consumed)
}

fn format_tree(nodes: &[RawNode], prefix: &str, out: &mut String) -> fmt::Result {
    for (i, node) in nodes.iter().enumerate() {
        let is_last = i + 1 == nodes.len();
        writeln!(
            out,
            "{}{}[{}] Tag: {} | Offset: 0x{:08x} | Words: {} ({} bytes) | Padding: {}",
            prefix,
            if is_last { "└── " } else { "├── " },
            i,
            format_tag_fourcc(node.header.tag),
            node.byte_offset,
            node.header.word_len,
            node.header.byte_len(),
            node.header.flags.padding_bytes()
        )?;
        let child_prefix = format!("{}{}", prefix, if is_last { "    " } else { "│   " });
        if let Some(preview) = &node.data_preview {
            writeln!(out, "{}Data: {}", child_prefix, preview)?;
        }
        if !node.children.is_empty() {
            writeln!(out, "{}Children:", child_prefix)?;
            format_tree(&node.children, &child_prefix, out)?;
        }
    }
    Ok(())
}

const RULE: &str = "=================================================================";

fn format_report(
    words: &[u32],
    nodes: &[RawNode],
    consumed: usize,
    out: &mut String,
) -> fmt::Result {
    writeln!(out, "{RULE}")?;
    writeln!(
        out,
        "                   OpenPRoT TLV File Inspector                   "
    )?;
    writeln!(out, "{RULE}")?;
    writeln!(
        out,
        "  Total Size     : {} bytes ({} words)",
        words.len() * 4,
        words.len()
    )?;
    writeln!(out, "  Root Containers: {}", nodes.len())?;
    writeln!(
        out,
        "-----------------------------------------------------------------"
    )?;
    writeln!(out, "  TLV Structure Tree:")?;
    format_tree(nodes, "  ", out)?;
    if consumed < words.len() {
        writeln!(
            out,
            "  Unparsed trailing: {} words at 0x{:08x}",
            words.len() - consumed,
            consumed * 4
        )?;
    }
    writeln!(out, "{RULE}")
}

/// Inspects a slice of 32-bit TLV words using the generic wire walker.
pub fn inspect_words(words: &[u32]) -> Result<String> {
    let (nodes, consumed) = walk(words, 0);
    ensure!(
        !nodes.is_empty(),
        "Malformed TLV record: no valid container stream"
    );

    let mut out = String::new();
    format_report(words, &nodes, consumed, &mut out).expect("writing to a String cannot fail");
    Ok(out)
}

/// Inspects a TLV byte slice using the generic wire walker.
pub fn inspect_file(bytes: &[u8]) -> Result<String> {
    ensure!(
        bytes.len().is_multiple_of(4),
        "Record bytes must be 4-byte aligned"
    );
    ensure!(!bytes.is_empty(), "Malformed TLV record: empty file");
    let words: Vec<u32> = bytes
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
        .collect();
    inspect_words(&words)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inspect_arbitrary_tlv_raw() {
        let words = [
            u32::from_le_bytes(*b"TEST"),
            2, // 2 words of payload, reserved=0, flags=0
            0x12345678,
            0x9abcdef0,
        ];
        let tlv_bytes = zerocopy::IntoBytes::as_bytes(&words[..]).to_vec();

        // Raw inspection succeeds without any schema knowledge:
        let report = inspect_file(&tlv_bytes).unwrap();
        assert!(report.contains("Tag: 'TEST'"));
        assert!(report.contains("TLV Structure Tree:"));
        assert!(report.contains("Words: 2 (8 bytes)"));
    }

    #[test]
    fn test_inspect_nested_tlv_raw() {
        let words = [
            u32::from_le_bytes(*b"ROOT"),
            3, // 3 words of payload (1 child container)
            u32::from_le_bytes(*b"CHLD"),
            1, // 1 word of payload
            0xdeadbeef,
        ];
        let tlv_bytes = zerocopy::IntoBytes::as_bytes(&words[..]).to_vec();

        let report = inspect_file(&tlv_bytes).unwrap();
        assert!(report.contains("Tag: 'ROOT'"));
        assert!(report.contains("Children:"));
        assert!(report.contains("Tag: 'CHLD'"));
    }

    #[test]
    fn test_partly_parsing_payload_is_shown_as_data() {
        // 'ROOT' holds 4 words. The first 3 are a well-formed 'CHLD' container,
        // but the 4th is left over. A payload is only a container stream when
        // its children consume it exactly, so this one is a leaf: the walker
        // must render it as a hex preview rather than invent a child tree.
        let words = [
            u32::from_le_bytes(*b"ROOT"),
            4,
            u32::from_le_bytes(*b"CHLD"),
            1,
            0xdeadbeef,
            0x11111111,
        ];
        let tlv_bytes = zerocopy::IntoBytes::as_bytes(&words[..]).to_vec();

        let report = inspect_file(&tlv_bytes).unwrap();
        assert!(report.contains("Tag: 'ROOT'"), "{report}");
        assert!(
            !report.contains("Children:"),
            "unexpected child tree:\n{report}"
        );
        assert!(
            !report.contains("Tag: 'CHLD'"),
            "unexpected child node:\n{report}"
        );
        assert!(
            report.contains("Data: "),
            "expected a hex preview:\n{report}"
        );
    }

    #[test]
    fn test_unparsed_trailing_words_are_reported() {
        // A valid 'GOOD' container followed by a 'TRNC' header claiming more
        // payload than remains. The walker stops at 'TRNC', and the report
        // must say so rather than look like a clean single-container file.
        let words = [
            u32::from_le_bytes(*b"GOOD"),
            1,
            0xdeadbeef,
            u32::from_le_bytes(*b"TRNC"),
            8,
            0x11111111,
        ];
        let tlv_bytes = zerocopy::IntoBytes::as_bytes(&words[..]).to_vec();

        let report = inspect_file(&tlv_bytes).unwrap();
        assert!(report.contains("Root Containers: 1"), "{report}");
        assert!(
            report.contains("Unparsed trailing: 3 words at 0x0000000c"),
            "{report}"
        );
    }

    #[test]
    fn test_invalid_alignment_and_empty() {
        let err = inspect_file(&[1, 2, 3]).unwrap_err().to_string();
        assert!(err.contains("4-byte aligned"), "{err}");

        let err = inspect_file(&[]).unwrap_err().to_string();
        assert!(err.contains("empty file"), "{err}");
    }
}
