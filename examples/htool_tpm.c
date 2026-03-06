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

#include "htool_tpm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "host_commands.h"
#include "htool.h"
#include "htool_cmd.h"
#include "transports/libhoth_device.h"

int htool_set_tpm_mode(const struct htool_invocation* inv) {
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  const char* mode_str = inv->cmd->verbs[2];

  uint32_t mode;
  if (strcmp(mode_str, "disabled") == 0) {
    mode = TPM_MODE_DISABLED;
  } else if (strcmp(mode_str, "tpm_spi") == 0) {
    mode = TPM_MODE_TPM_SPI;
  } else if (strcmp(mode_str, "spi_nor_mailbox") == 0) {
    mode = TPM_MODE_SPI_NOR_MAILBOX;
  } else {
    fprintf(stderr, "Invalid mode value: %s\n", mode_str);
    fprintf(stderr, "Valid modes are: disabled, tpm_spi, spi_nor_mailbox\n");
    return -1;
  }

  struct tpm_mode req = {
      .mode = mode,
  };

  return libhoth_hostcmd_exec(
      dev, HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_SET_TPM_MODE, 0, &req,
      sizeof(req), NULL, 0, NULL);
}

int htool_get_tpm_mode(const struct htool_invocation* inv) {
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  struct tpm_mode resp;
  int ret = libhoth_hostcmd_exec(
      dev, HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_GET_TPM_MODE, 0, NULL, 0,
      &resp, sizeof(resp), NULL);
  if (ret) {
    return ret;
  }

  const char* mode_str;
  switch (resp.mode) {
    case TPM_MODE_DISABLED:
      mode_str = "DISABLED";
      break;
    case TPM_MODE_TPM_SPI:
      mode_str = "TPM_SPI";
      break;
    case TPM_MODE_SPI_NOR_MAILBOX:
      mode_str = "SPI_NOR_MAILBOX";
      break;
    default:
      mode_str = "UNKNOWN";
      break;
  }
  printf("TPM mode: %s (%u)\n", mode_str, resp.mode);

  return 0;
}
