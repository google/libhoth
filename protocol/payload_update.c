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
#include <unistd.h>

#include "command_version.h"
#include "host_cmd.h"
#include "payload_info.h"
#include "progress.h"
#include "transports/libhoth_device.h"
#include "util.h"

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

static int payload_update_erase(struct libhoth_device* const dev,
                                const size_t offset, const size_t len) {
  struct payload_update_packet request;
  request.type = PAYLOAD_UPDATE_ERASE;
  request.offset = offset;
  request.len = len;
  return libhoth_hostcmd_exec(
      dev, HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HOTH_PAYLOAD_UPDATE, 0,
      &request, sizeof(request), NULL, 0, NULL);
}

enum payload_update_err libhoth_payload_update(struct libhoth_device* dev,
                                               uint8_t* image, size_t size,
                                               bool skip_erase) {
  if (libhoth_find_image_descriptor(image, size) == NULL) {
    return PAYLOAD_UPDATE_BAD_IMG;
  }

  if (!skip_erase) {
    struct libhoth_progress_stderr erase_progress;
    libhoth_progress_stderr_init(&erase_progress, "Erase staging side");

    const size_t block_erase = 64 * 1024;
    const size_t sector_erase = 4 * 1024;

    const bool is_image_size_sector_aligned = ((size % sector_erase) == 0);
    if (!is_image_size_sector_aligned) {
      fprintf(stderr, "error: image size (0x%zx) is not sector-aligned.\n",
              size);
      return PAYLOAD_UPDATE_IMAGE_NOT_SECTOR_ALIGNED;
    }

    // Erase by blocks as much as possible.
    size_t offset = 0;
    for (; offset + block_erase <= size; offset += block_erase) {
      const int ret = payload_update_erase(dev, offset, block_erase);
      if (ret != 0) {
        fprintf(stderr, "block erase offset 0x%zx err: %d\n", offset, ret);
        return PAYLOAD_UPDATE_ERASE_FAIL;
      }
      erase_progress.progress.func(erase_progress.progress.param, offset, size);
    }

    // Erase remaining by sectors.
    for (; offset + sector_erase <= size; offset += sector_erase) {
      const int ret = payload_update_erase(dev, offset, sector_erase);
      if (ret != 0) {
        fprintf(stderr, "sector erase offset 0x%zx err: %d\n", offset, ret);
        return PAYLOAD_UPDATE_ERASE_FAIL;
      }
      erase_progress.progress.func(erase_progress.progress.param, offset, size);
    }
  }

  const size_t max_chunk_size = LIBHOTH_MAILBOX_SIZE -
                                sizeof(struct hoth_host_request) -
                                sizeof(struct payload_update_packet);

  struct libhoth_progress_stderr program_progress;
  libhoth_progress_stderr_init(&program_progress, "Sending payload");
  for (size_t offset = 0; offset < size; ++offset) {
    program_progress.progress.func(program_progress.progress.param, offset,
                                   size);

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

enum payload_update_err libhoth_payload_update_read_chunk(
    struct libhoth_device* dev, int fd, size_t len, size_t offset) {
  const size_t max_chunk_size =
      LIBHOTH_MAILBOX_SIZE - sizeof(struct hoth_host_response);
  uint8_t buffer[LIBHOTH_MAILBOX_SIZE];

  struct payload_update_packet pkt;

  pkt.type = PAYLOAD_UPDATE_READ;

  while (len > 0) {
    size_t chunk_size = (len < max_chunk_size) ? len : max_chunk_size;

    pkt.offset = offset;
    pkt.len = chunk_size;

    int ret = libhoth_hostcmd_exec(
        dev, HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HOTH_PAYLOAD_UPDATE, 0,
        &pkt, sizeof(pkt), &buffer, chunk_size, NULL);

    if (ret != 0) {
      fprintf(stderr, "Payload read failed, err code: %d\n", ret);
      return PAYLOAD_UPDATE_READ_FAIL;
    }

    ret = libhoth_force_write(fd, buffer, chunk_size);
    if (ret != 0) {
      fprintf(stderr,
              "Failed to write payload during payload read, err code: %d\n",
              ret);
      return PAYLOAD_UPDATE_READ_FAIL;
    }

    len -= chunk_size;
    offset += chunk_size;
  }

  return PAYLOAD_UPDATE_OK;
}
