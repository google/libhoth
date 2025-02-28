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

//#![no_std]

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

// Based on https://chromium.googlesource.com/chromiumos/third_party/cryptoc/+/refs/heads/main/sha256.c

static K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const BLOCK_SIZE_BYTES: usize = 64;
const BLOCK_SIZE_WORDS: usize = BLOCK_SIZE_BYTES / 4;

pub struct Sha256 {
    state: [u32; 8],
    block: [u32; BLOCK_SIZE_WORDS],
    count: u64,
}
impl Sha256 {
    pub const fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            block: [0; 16],
            count: 0,
        }
    }
    pub const fn update(&mut self, data: &[u8]) {
        let mut i = (self.count as usize) % BLOCK_SIZE_BYTES;

        self.count += data.len() as u64;

        let mut src_index = 0;
        while src_index < data.len() {
            self.block_bytes_mut()[i] = data[src_index];
            i += 1;
            src_index += 1;
            if i == 64 {
                self.transform();
                i = 0;
            }
        }
    }

    pub const fn finalize(mut self) -> [u8; 32] {
        let bit_count: u64 = self.count * 8;

        // Write byte indicating end of message
        self.update(&[0x80]);

        let bytes_in_block = (self.count as usize) % BLOCK_SIZE_BYTES;
        if bytes_in_block > BLOCK_SIZE_BYTES - 8 {
            // There is no space for the 64-bit bit-count in this block; pad it out and start a new one
            self.pad_remaining_bytes_in_block();
            self.transform();
        }

        self.pad_remaining_bytes_in_block();
        self.block[14] = ((bit_count >> 32) as u32).to_be();
        self.block[15] = (bit_count as u32).to_be();
        self.transform();

        let mut result = [0_u32; 8];
        let mut t = 0;
        while t < 8 {
            result[t] = self.state[t].to_be();
            t += 1;
        }
        unsafe { core::mem::transmute::<[u32; 8], [u8; 32]>(result) }
    }
    const fn block_bytes_mut(&mut self) -> &mut [u8; 64] {
        // Would prefer to use zerocopy, but traits from const aren't possible today.
        unsafe { core::mem::transmute::<&mut [u32; 16], &mut [u8; 64]>(&mut self.block) }
    }
    const fn pad_remaining_bytes_in_block(&mut self) {
        let bytes_in_block = (self.count as usize) % BLOCK_SIZE_BYTES;
        let mut t = bytes_in_block;
        while t < BLOCK_SIZE_BYTES {
            self.block_bytes_mut()[t] = 0;
            t += 1;
        }
        self.count += (BLOCK_SIZE_BYTES - bytes_in_block) as u64;
    }

    const fn transform(&mut self) {
        let ror = u32::rotate_right;
        const fn shr(a: u32, b: u32) -> u32 {
            a >> b
        }

        let mut w = [0_u32; 64];
        let mut t = 0;
        while t < 16 {
            w[t] = u32::from_be(self.block[t]);
            t += 1;
        }
        while t < 64 {
            let s0 = ror(w[t - 15], 7) ^ ror(w[t - 15], 18) ^ shr(w[t - 15], 3);
            let s1 = ror(w[t - 2], 17) ^ ror(w[t - 2], 19) ^ shr(w[t - 2], 10);
            w[t] = w[t - 16]
                .wrapping_add(s0)
                .wrapping_add(w[t - 7])
                .wrapping_add(s1);
            t += 1;
        }
        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        let mut t = 0;
        while t < 64 {
            let s0 = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            let s1 = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[t])
                .wrapping_add(w[t]);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
            t += 1;
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}
impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut sha = Sha256::new();
    sha.update(data);
    sha.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn smoke_test() {
        assert_eq!(
            sha256(b""),
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55,
            ]
        );
        assert_eq!(
            sha256(b" "),
            [
                0x36, 0xa9, 0xe7, 0xf1, 0xc9, 0x5b, 0x82, 0xff, 0xb9, 0x97, 0x43, 0xe0, 0xc5, 0xc4,
                0xce, 0x95, 0xd8, 0x3c, 0x9a, 0x43, 0x0a, 0xac, 0x59, 0xf8, 0x4e, 0xf3, 0xcb, 0xfa,
                0xb6, 0x14, 0x50, 0x68,
            ]
        );
        assert_eq!(
            sha256(b"Hello World!"),
            [
                0x7f, 0x83, 0xb1, 0x65, 0x7f, 0xf1, 0xfc, 0x53, 0xb9, 0x2d, 0xc1, 0x81, 0x48, 0xa1,
                0xd6, 0x5d, 0xfc, 0x2d, 0x4b, 0x1f, 0xa3, 0xd6, 0x77, 0x28, 0x4a, 0xdd, 0xd2, 0x00,
                0x12, 0x6d, 0x90, 0x69,
            ],
        );
        // length 16
        assert_eq!(
            sha256(b"Ys2e4brsOcz0fIZu"),
            [
                0xfb, 0xcd, 0x11, 0x34, 0x82, 0xf6, 0x2e, 0x10, 0x6c, 0xe6, 0x29, 0x89, 0x99, 0xeb,
                0x18, 0x8d, 0x92, 0x20, 0x69, 0xe1, 0x56, 0xb0, 0x64, 0xeb, 0xd5, 0x21, 0x65, 0xed,
                0xe2, 0xfc, 0x23, 0x09,
            ]
        );

        // length 31
        assert_eq!(
            sha256(b"RAS4uaNDbAs9TlKRTj2M7g4tyCzcgZL"),
            [
                0x93, 0xde, 0x27, 0xca, 0x5d, 0x8f, 0x01, 0x9b, 0x29, 0x41, 0x33, 0xfa, 0x02, 0x76,
                0x99, 0x58, 0x8a, 0xb7, 0xec, 0x2b, 0x74, 0x2e, 0x47, 0x0a, 0x40, 0x93, 0x7b, 0x24,
                0x8b, 0x24, 0x02, 0x66,
            ]
        );

        // length 32
        assert_eq!(
            sha256(b"ir41RSmtB3jDFJyHzOUlE0fug763ZRDh"),
            [
                0xee, 0xd7, 0x44, 0x98, 0x05, 0x4d, 0x7c, 0x35, 0xfb, 0x7d, 0x16, 0x02, 0x81, 0x8b,
                0x84, 0x53, 0xa0, 0x30, 0xb2, 0xc2, 0x7c, 0x4a, 0x44, 0xbd, 0x77, 0xbe, 0xbb, 0x26,
                0x57, 0x16, 0x27, 0xa0
            ],
        );
        // length 55
        assert_eq!(
            b"iZOB3ptdlWmgVdSYIWOxgR1M3NmJIDE8Uu54SsKsX+1anla5q82mg7a".len(),
            55
        );
        assert_eq!(
            sha256(b"iZOB3ptdlWmgVdSYIWOxgR1M3NmJIDE8Uu54SsKsX81anla5q82mg7a"),
            [
                0x78, 0x18, 0x60, 0xe5, 0x5e, 0x5e, 0x23, 0x1e, 0x5d, 0xda, 0x2a, 0xdd, 0xa5, 0xee,
                0x6d, 0x95, 0x84, 0xac, 0x0c, 0xf3, 0xec, 0x09, 0xd2, 0x2b, 0x4a, 0x13, 0xcf, 0x0e,
                0x10, 0xd3, 0x06, 0xef,
            ]
        );

        // length 56 (fits in exactly one block)
        assert_eq!(
            sha256(b"7OJe1chgSma4phwrwoiRV8UXMVuq9q2zUeqQ21KUZHEUnY7FUdj29xke"),
            [
                0x9e, 0x52, 0x75, 0x5c, 0x0d, 0x12, 0x18, 0x65, 0x83, 0x4e, 0x97, 0xfe, 0x13, 0x1c,
                0x00, 0x1f, 0xef, 0x28, 0xd7, 0x37, 0xb3, 0x47, 0x54, 0xdd, 0x44, 0x31, 0x09, 0xd5,
                0x74, 0xce, 0x61, 0x7f,
            ]
        );

        // length 57 (expands to two blocks)
        assert_eq!(
            sha256(b"Z6A0YmIVthygYJjbTWB3DjJCOVcf9nycCH0e5oCBlTPFysnj1XnhEdP3F"),
            [
                0xd5, 0xde, 0xcc, 0x3e, 0x60, 0xbe, 0xfe, 0x45, 0xe8, 0x1a, 0xf1, 0xad, 0x11, 0x7c,
                0xff, 0x97, 0x5d, 0xb8, 0x58, 0xf8, 0x4c, 0xcf, 0x8a, 0x15, 0x2c, 0x35, 0x51, 0x49,
                0x72, 0xff, 0x45, 0x1f,
            ]
        );

        // length 63
        assert_eq!(
            sha256(b"k3uIvGDoDYximAaerV1IxNUJczk8Dg7aGC6cxh3z2e3otSwhOZQhAdlSjLovgxc"),
            [
                0x15, 0xfb, 0xb2, 0x73, 0x73, 0xdb, 0xaa, 0x4a, 0xcc, 0x32, 0x77, 0x36, 0x36, 0xf3,
                0xad, 0xab, 0x95, 0xc4, 0xaa, 0xcc, 0x65, 0x77, 0x81, 0xa4, 0x3c, 0x38, 0x64, 0x12,
                0x37, 0x11, 0xce, 0xee,
            ]
        );

        // length 64
        assert_eq!(
            sha256(b"HizlgtPfn57DwXecYifNBO9wL7hGGSdCrIPe3zWpmIPyBF0xpkS8ThN1nsXmvztQ"),
            [
                0x9c, 0x66, 0x96, 0xd5, 0x81, 0xfc, 0x4c, 0x60, 0xa5, 0x39, 0x9b, 0xd6, 0xa8, 0x19,
                0xca, 0xcd, 0xc1, 0xf7, 0x92, 0xc2, 0x55, 0x84, 0x3f, 0xbe, 0x4b, 0x20, 0xa2, 0x0f,
                0xa5, 0xbd, 0x16, 0x22,
            ]
        );
        // length 65
        assert_eq!(
            sha256(b"lTVBIeYnVtawL4VVe3NXXIyLGd8s4PPMcfOnijH9HSluYojeueNPtcrormvbp0H70"),
            [
                0xa3, 0xe1, 0xdb, 0xbb, 0xdc, 0xa8, 0x82, 0xe9, 0x0a, 0xf0, 0xcf, 0xf0, 0x7c, 0xba,
                0x36, 0xf3, 0x08, 0x54, 0x32, 0x41, 0x60, 0x1c, 0xe3, 0xcb, 0xfd, 0x19, 0xf6, 0x0e,
                0x93, 0xed, 0x41, 0xd4,
            ]
        );
        // length 120
        assert_eq!(
            sha256(b"R7ncj4usgKjwECA5WkHHkOxtasOj8oPKPVJjo1Y326jLilcgg702uSiD9zz3K0XXMzGh88MDfUhCgbQgQRpPx2FFzqXSmDR5CfS1VOkk7wZuDz6JwTV44US2"),
            [
                0x95, 0x10, 0xe5, 0x70, 0x38, 0xd4, 0xb1, 0x52, 0x82, 0x06,
                0x8d, 0x0c, 0x2d, 0x5f, 0xe9, 0x18, 0xf9, 0xcf, 0xc3, 0xa5,
                0x74, 0x22, 0x95, 0x9b, 0x42, 0x90, 0xc6, 0x5b, 0x32, 0xc5,
                0x02, 0x24
            ]
        );
        // length 121 (3 blocks)
        assert_eq!(
            sha256(b"2oRV9iFl4FE1hiEkIjATkgMJJbWNMUWHoLB8x603j86Gsy1SqLRVQ0uTFydUvrJrWfItaS0ulIano9mifBWRVNv4GhsPIpYnYJFbSL4m1h83OAzpHhULf90xO"),
            [
                0x0f, 0xa0, 0xd2, 0xef, 0x94, 0x38, 0x87, 0x80, 0x92, 0xc4,
                0x1c, 0x60, 0xc5, 0x9d, 0xcb, 0xe9, 0x32, 0xcb, 0x2d, 0x8b,
                0x3a, 0x52, 0x7a, 0xd4, 0x67, 0xb4, 0xfa, 0x8f, 0x96, 0x84,
                0x36, 0x4a,
            ]
        )
    }
}
