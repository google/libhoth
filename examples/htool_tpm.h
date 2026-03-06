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

#ifndef LIBHOTH_EXAMPLES_HTOOL_TPM_H_
#define LIBHOTH_EXAMPLES_HTOOL_TPM_H_

#include "htool_cmd.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HOTH_PRV_CMD_SET_TPM_MODE 0x0051
#define HOTH_PRV_CMD_GET_TPM_MODE 0x0052

enum ec_tpm_mode {
  TPM_MODE_DISABLED = 0,  // Turn the TPM off: typically used to turn off one
                          // TPM in 1x2Socket mode
  TPM_MODE_TPM_SPI = 1,   // TPM SPI wire protocol (TCG standard)
  TPM_MODE_SPI_NOR_MAILBOX = 2,  // SPI EEPROM protocol tunneled through the
                                 // mailbox/host command
};
struct tpm_mode {
  uint8_t mode;  // enum ec_tpm_mode
  uint8_t reserved[3];
} __attribute__((packed, aligned(4)));

int htool_set_tpm_mode(const struct htool_invocation* inv);
int htool_get_tpm_mode(const struct htool_invocation* inv);

#ifdef __cplusplus
}
#endif

#endif  // LIBHOTH_EXAMPLES_HTOOL_TPM_H_
