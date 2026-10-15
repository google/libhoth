// Copyright 2025 Google LLC
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

#ifndef LIBHOTH_EXAMPLES_HTOOL_SECURITY_V2_DEFS_H_
#define LIBHOTH_EXAMPLES_HTOOL_SECURITY_V2_DEFS_H_

#include <stdint.h>

// Elliptic Curve signature as per the NIST P256 standard. All fields are
// little-endian with a 32-bit word size. p256_from_le_bin can be used to get a
// usable pair of p256_ints.
struct ec_p256_signature {
  // The r parameter of the EC P256 signature. 32 bytes.
  uint8_t r[32];
  // The s parameter of the EC P256 signature. 32 bytes.
  uint8_t s[32];
};

// Elliptic Curve public key as per the NIST P256 standard. All fields are
// little-endian with a 32-bit word size. p256_from_le_bin can be used to get a
// usable pair of p256_ints.
struct ec_p256_public_key {
  // The x coordinate of the EC P256 public key. 32 bytes.
  uint8_t q_a_x[32];
  // The y coordinate of the EC P256 public key. 32 bytes.
  uint8_t q_a_y[32];
};

#endif
