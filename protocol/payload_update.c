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

#include "payload_update.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "command_version.h"
#include "host_cmd.h"
#include "payload_info.h"
#include "transports/libhoth_device.h"

static int send_payload_update_request_with_command(struct libhoth_device* dev,
                                                    uint8_t command) {
  struct payload_update_packet request;
  request.type = command;
  request.offset = 0;
  request.len = 0;

  int ret = libhoth_hostcmd_exec(
      dev, HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HOTH_PAYLOAD_UPDATE, 0,
      &request, sizeof(request), NULL, 0, NULL);
  if (ret != 0) {
    fprintf(stderr, "Error code from hoth: %d\n", ret);
    return -1;
  }
  return 0;
}

static int libhoth_payload_update_finalize(
    struct libhoth_device* dev, uint8_t* pld_needs_reinitialization) {
  uint32_t version_mask = 0;
  int status = libhoth_get_command_versions(
      dev, HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HOTH_PAYLOAD_UPDATE,
      &version_mask);
  // Command version check in not supported or version 1 is not supported,
  // default to version 0.
  if (status == HTOOL_ERROR_HOST_COMMAND_START + HOTH_RES_INVALID_COMMAND ||
      (status == 0 && (version_mask & 0x2) == 0)) {
    fprintf(stderr, "Using payload update version 0\n");
    if (pld_needs_reinitialization != NULL) {
      *pld_needs_reinitialization = 0;
    }
    return send_payload_update_request_with_command(dev,
                                                    PAYLOAD_UPDATE_FINALIZE);
  } else if (status != 0) {
    fprintf(stderr,
            "Checking supported command version got unexpected error: %d\n",
            status);
    return status;
  }
  fprintf(stderr, "Using payload update version 1\n");
  struct payload_update_packet request = {
      .type = PAYLOAD_UPDATE_FINALIZE,
  };
  struct payload_update_finalize_response_v1 response = {0};
  status = libhoth_hostcmd_exec(
      dev, HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HOTH_PAYLOAD_UPDATE,
      /*version=*/1, &request, sizeof(request), &response, sizeof(response),
      NULL);
  if (status != 0) {
    return status;
  }
  if (pld_needs_reinitialization != NULL) {
    *pld_needs_reinitialization = response.pld_needs_reinitialization;
  }
  return 0;
}

enum payload_update_err libhoth_payload_update(struct libhoth_device* dev,
                                               uint8_t* image, size_t size) {
  if (libhoth_find_image_descriptor(image, size) == NULL) {
    return PAYLOAD_UPDATE_BAD_IMG;
  }

  fprintf(stderr, "Initiating payload update protocol with libhoth.\n");
  if (send_payload_update_request_with_command(dev, PAYLOAD_UPDATE_INITIATE) !=
      0) {
    return PAYLOAD_UPDATE_INITIATE_FAIL;
  }

  const size_t max_chunk_size = LIBHOTH_MAILBOX_SIZE -
                                sizeof(struct hoth_host_request) -
                                sizeof(struct payload_update_packet);

  fprintf(stderr, "Flashing the image to hoth.\n");
  for (size_t offset = 0; offset < size; ++offset) {
    if (image[offset] == 0xFF) {
      continue;
    }
    struct payload_update_packet request;

    size_t chunk_size = max_chunk_size;
    if (size - offset < chunk_size) {
      chunk_size = size - offset;
    }

    while (chunk_size > 0 && image[offset + chunk_size - 1] == 0xFF) {
      --chunk_size;
    }

    if (chunk_size == 0) {
      continue;
    }

    request.offset = offset;
    request.len = chunk_size;
    request.type = PAYLOAD_UPDATE_CONTINUE;

    uint8_t buffer[sizeof(struct payload_update_packet) + LIBHOTH_MAILBOX_SIZE];
    memcpy(buffer, &request, sizeof(request));
    memcpy(buffer + sizeof(request), image + offset, chunk_size);

    int ret = libhoth_hostcmd_exec(
        dev, HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HOTH_PAYLOAD_UPDATE, 0,
        buffer, sizeof(request) + chunk_size, NULL, 0, NULL);
    if (ret != 0) {
      fprintf(stderr, "Error code from hoth: %d\n", ret);
      return PAYLOAD_UPDATE_FLASH_FAIL;
    }

    offset += chunk_size - 1;
  }

  fprintf(stderr, "Finalizing payload update.\n");
  uint8_t pld_needs_reinitialization = 0;
  if (libhoth_payload_update_finalize(dev, &pld_needs_reinitialization) != 0) {
    return PAYLOAD_UPDATE_FINALIZE_FAIL;
  }
  if (pld_needs_reinitialization != 0) {
    fprintf(stderr, "PLD updated. Re-initialization needed.\n");
  }

  return PAYLOAD_UPDATE_OK;
}

int libhoth_payload_update_getstatus(
    struct libhoth_device* dev, struct payload_update_status* update_status) {
  struct payload_update_packet request;
  request.type = PAYLOAD_UPDATE_GET_STATUS;
  request.offset = 0;
  request.len = 0;

  size_t rlen = 0;
  int ret = libhoth_hostcmd_exec(
      dev, HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HOTH_PAYLOAD_UPDATE, 0,
      &request, sizeof(request), update_status, sizeof(*update_status), &rlen);

  if (ret != 0) {
    fprintf(stderr, "HOTH_PAYLOAD_UPDATE_GET_STATUS error code: %d\n", ret);
    return ret;
  }

  if (rlen != sizeof(*update_status)) {
    fprintf(stderr,
            "HOTH_PAYLOAD_UPDATE_GET_STATUS expected exactly %ld response "
            "bytes, got %ld\n",
            sizeof(*update_status), rlen);
    return -1;
  }

  return 0;
}
