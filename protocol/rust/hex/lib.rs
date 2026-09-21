// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Hex display utilities.
//!
//! This crate provides utilities for displaying bytes as hex strings, primarily
//! for logging and debugging.
//!
//! These routines are optimized for code-size in embedded targets.

#![cfg_attr(not(test), no_std)]

/// A helper for writing out hex bytes to ufmt or core::fmt.
///
/// Example:
///
/// ```
/// use libhoth_hex::HexDisplay;
///
/// let data = &[0xba, 0x5e, 0xba, 0x11];
/// assert_eq!(format!("{}", HexDisplay(data)), "ba5eba11");
/// assert_eq!(format!("{:?}", HexDisplay(data)), "[0xba, 0x5e, 0xba, 0x11, ]");
/// ```
pub struct HexDisplay<'a>(pub &'a [u8]);

impl ufmt::uDisplay for HexDisplay<'_> {
    fn fmt<W>(&self, f: &mut ufmt::Formatter<'_, W>) -> Result<(), W::Error>
    where
        W: ufmt::uWrite + ?Sized,
    {
        for b in self.0 {
            f.write_str(HexByte::from(*b).as_str())?;
        }
        Ok(())
    }
}

impl ufmt::uDebug for HexDisplay<'_> {
    fn fmt<W: ufmt::uWrite + ?Sized>(
        &self,
        f: &mut ufmt::Formatter<'_, W>,
    ) -> Result<(), W::Error> {
        f.write_str("[")?;
        let mut literal = HexLiteral::new();
        for b in self.0 {
            literal.set(HexByte::from(*b));
            f.write_str(literal.as_str())?;
        }
        f.write_str("]")?;
        Ok(())
    }
}

impl core::fmt::Display for HexDisplay<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for b in self.0 {
            f.write_str(HexByte::from(*b).as_str())?;
        }
        Ok(())
    }
}

impl core::fmt::Debug for HexDisplay<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[")?;
        let mut literal = HexLiteral::new();
        for b in self.0 {
            literal.set(HexByte::from(*b));
            f.write_str(literal.as_str())?;
        }
        f.write_str("]")?;
        Ok(())
    }
}

mod hex_byte {
    pub struct HexByte([u8; 2]);
    impl HexByte {
        pub const fn as_str(&self) -> &str {
            // Safety: HEX_DIGITS contains only ASCII characters, so buf is
            // definitely valid utf-8. This can be made safe once core::ascii::Char
            // is stabilized.
            unsafe { core::str::from_utf8_unchecked(&self.0) }
        }
    }
    impl From<u8> for HexByte {
        fn from(b: u8) -> Self {
            const HEX_DIGITS: [u8; 16] = *b"0123456789abcdef";
            Self([
                HEX_DIGITS[usize::from((b >> 4) & 0xf)],
                HEX_DIGITS[usize::from(b & 0xf)],
            ])
        }
    }
}
use hex_byte::HexByte;

mod hex_literal {
    use super::HexByte;

    pub struct HexLiteral([u8; 6]);
    impl HexLiteral {
        pub fn new() -> Self {
            Self(*b"0x--, ")
        }
        pub fn set(&mut self, byte: HexByte) {
            self.0[2..4].copy_from_slice(byte.as_str().as_bytes())
        }
        pub const fn as_str(&self) -> &str {
            // Safety: This string only contains ASCII characters.
            unsafe { core::str::from_utf8_unchecked(&self.0) }
        }
    }
}
use hex_literal::HexLiteral;

#[cfg(test)]
mod test {
    use super::*;
    use ufmt::uWrite;
    use ufmt::uwrite;

    struct StringWriter(String);
    impl uWrite for StringWriter {
        type Error = ();

        fn write_str(&mut self, s: &str) -> Result<(), Self::Error> {
            self.0.push_str(s);
            Ok(())
        }
    }

    #[test]
    fn test_hex_udisplay() {
        let mut writer = StringWriter(String::new());

        uwrite!(&mut writer, "{}", HexDisplay(&[])).unwrap();
        assert_eq!(writer.0, "");

        uwrite!(&mut writer, "{}", HexDisplay(&[0xba, 0x5e, 0xba, 0x11])).unwrap();
        assert_eq!(writer.0, "ba5eba11");

        uwrite!(&mut writer, "{}", HexDisplay(&[0x12, 0x34, 0x56])).unwrap();
        assert_eq!(writer.0, "ba5eba11123456");
    }

    #[test]
    fn test_hex_udebug() {
        let mut writer = StringWriter(String::new());
        uwrite!(&mut writer, "{:?}", HexDisplay(&[])).unwrap();
        assert_eq!(writer.0, "[]");

        let mut writer = StringWriter(String::new());
        uwrite!(&mut writer, "{:?}", HexDisplay(&[0xba, 0x5e])).unwrap();
        assert_eq!(writer.0, "[0xba, 0x5e, ]");
    }

    #[test]
    fn test_hex_display() {
        assert_eq!(format!("{}", HexDisplay(&[])), "");
        assert_eq!(
            format!("{}", HexDisplay(&[0xba, 0x5e, 0xba, 0x11])),
            "ba5eba11"
        );
        assert_eq!(
            format!(
                "{}",
                HexDisplay(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef])
            ),
            "0123456789abcdef"
        );
    }

    #[test]
    fn test_hex_debug() {
        assert_eq!(format!("{:?}", HexDisplay(&[])), "[]");
        assert_eq!(
            format!("{:?}", HexDisplay(&[0xba, 0x5e, 0xba, 0x11])),
            "[0xba, 0x5e, 0xba, 0x11, ]"
        );
    }
}
