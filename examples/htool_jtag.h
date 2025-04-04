// Copyright 2024 Google LLC
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

#ifndef LIBHOTH_EXAMPLES_HTOOL_JTAG_H_
#define LIBHOTH_EXAMPLES_HTOOL_JTAG_H_

#ifdef __cplusplus
extern "C" {
#endif

#define JTAG_READ_IDCODE_CMD_STR "read_idcode"
#define JTAG_TEST_BYPASS_CMD_STR "test_bypass"
#define JTAG_PROGRAM_AND_VERIFY_PLD_CMD_STR "program_and_verify_pld"
#define JTAG_VERIFY_PLD_CMD_STR "verify_pld"

// Forward declaration
struct htool_invocation;

int htool_jtag_run(const struct htool_invocation* inv);

#ifdef __cplusplus
}
#endif

#endif  // LIBHOTH_EXAMPLES_HTOOL_JTAG_H_
