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

use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;

/// A 64-bit integer type that is represented as 2 32-bit words; useful
/// on 32-bit microcontrollers that can't efficiently read unaligned 32-bit
/// words.
#[derive(Clone, Copy, Default, Eq, PartialEq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct U64Align4 {
    pub low: u32,
    pub high: u32,
}

impl U64Align4 {
    pub const fn new(val: u64) -> Self {
        Self {
            low: val as u32,
            high: (val >> 32) as u32,
        }
    }

    pub const fn get(self) -> u64 {
        self.low as u64 | ((self.high as u64) << 32)
    }
}

impl From<U64Align4> for u64 {
    fn from(value: U64Align4) -> Self {
        value.get()
    }
}

impl From<u64> for U64Align4 {
    fn from(value: u64) -> Self {
        Self::new(value)
    }
}

impl core::fmt::Display for U64Align4 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(&u64::from(*self), f)
    }
}

impl core::fmt::LowerHex for U64Align4 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::LowerHex::fmt(&u64::from(*self), f)
    }
}

impl core::fmt::Debug for U64Align4 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(&u64::from(*self), f)
    }
}

#[cfg(feature = "ufmt")]
impl ufmt::uDisplay for U64Align4 {
    fn fmt<W: ufmt::uWrite + ?Sized>(
        &self,
        f: &mut ufmt::Formatter<'_, W>,
    ) -> Result<(), W::Error> {
        ufmt::uDisplay::fmt(&u64::from(*self), f)
    }
}

#[cfg(feature = "ufmt")]
impl ufmt::uDisplayHex for U64Align4 {
    fn fmt_hex<W: ufmt::uWrite + ?Sized>(
        &self,
        f: &mut ufmt::Formatter<'_, W>,
        options: ufmt::HexOptions,
    ) -> Result<(), W::Error> {
        ufmt::uDisplayHex::fmt_hex(&u64::from(*self), f, options)
    }
}

#[cfg(feature = "ufmt")]
impl ufmt::uDebug for U64Align4 {
    fn fmt<W: ufmt::uWrite + ?Sized>(
        &self,
        f: &mut ufmt::Formatter<'_, W>,
    ) -> Result<(), W::Error> {
        ufmt::uDebug::fmt(&u64::from(*self), f)
    }
}

#[cfg(test)]
mod test {
    #[cfg(feature = "ufmt")]
    use ufmt::uwrite;

    use super::*;

    #[cfg(feature = "ufmt")]
    struct Buffer<const N: usize> {
        buf: [u8; N],
        len: usize,
    }

    #[cfg(feature = "ufmt")]
    impl<const N: usize> Buffer<N> {
        fn new() -> Self {
            Self {
                buf: [0; N],
                len: 0,
            }
        }
        fn as_bytes(&self) -> &[u8] {
            &self.buf[..self.len]
        }
    }

    #[cfg(feature = "ufmt")]
    impl<const N: usize> ufmt::uWrite for Buffer<N> {
        type Error = ();
        fn write_str(&mut self, s: &str) -> Result<(), Self::Error> {
            let bytes = s.as_bytes();
            if self.len + bytes.len() > N {
                return Err(());
            }
            self.buf[self.len..self.len + bytes.len()].copy_from_slice(bytes);
            self.len += bytes.len();
            Ok(())
        }
    }

    #[test]
    pub fn test_unaligned_u64() {
        assert_eq!(
            U64Align4::new(0xcd65_0941_8884_3461),
            U64Align4 {
                low: 0x8884_3461,
                high: 0xcd65_0941,
            }
        );
        assert_eq!(
            U64Align4 {
                low: 0x8884_3461,
                high: 0xcd65_0941,
            }
            .get(),
            0xcd65_0941_8884_3461
        );
        assert_eq!(
            u64::from(U64Align4::new(0xabbc_3d97_ecfc_8aae)),
            0xabbc_3d97_ecfc_8aae,
        );
        assert_eq!(
            U64Align4::from(0xd172_0953_6a66_d89e),
            U64Align4::new(0xd172_0953_6a66_d89e),
        );
        assert_eq!(
            format!("{}", U64Align4::new(15092135555144013982)),
            "15092135555144013982",
        );
        assert_eq!(
            format!("{:?}", U64Align4::new(15092135555144013982)),
            "15092135555144013982",
        );
        assert_eq!(
            format!("{:x}", U64Align4::new(0xd17209536a66d89e)),
            "d17209536a66d89e",
        );

        #[cfg(feature = "ufmt")]
        {
            let mut buf = Buffer::<32>::new();
            uwrite!(&mut buf, "{}", U64Align4::new(15092135555144013982)).unwrap();
            assert_eq!(buf.as_bytes(), b"15092135555144013982");

            let mut buf = Buffer::<32>::new();
            uwrite!(&mut buf, "{:?}", U64Align4::new(15092135555144013982)).unwrap();
            assert_eq!(buf.as_bytes(), b"15092135555144013982");

            let mut buf = Buffer::<32>::new();
            uwrite!(&mut buf, "{:x}", U64Align4::new(15092135555144013982)).unwrap();
            assert_eq!(buf.as_bytes(), b"d17209536a66d89e");
        }
    }
}
