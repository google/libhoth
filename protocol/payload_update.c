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

#include "protocol/payload_update.h"

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "protocol/command_version.h"
#include "protocol/host_cmd.h"
#include "protocol/payload_info.h"
#include "protocol/progress.h"
#include "protocol/status.h"
#include "protocol/util.h"
#include "transports/libhoth_device.h"

#define PAYLOAD_UPDATE_CONFIRM_OP_ENABLE 0
#define PAYLOAD_UPDATE_CONFIRM_OP_ENABLE_WITH_TIMEOUT 1
#define PAYLOAD_UPDATE_CONFIRM_OP_DISABLE 2
#define PAYLOAD_UPDATE_CONFIRM_OP_CONFIRM 3
#define PAYLOAD_UPDATE_CONFIRM_OP_GET_STAGED_TIMEOUT_VALUES 4

static libhoth_error send_payload_update_request_with_command(
    struct libhoth_device* dev, uint8_t command) {
  struct payload_update_packet request;
  request.type = command;
  request.offset = 0;
  request.len = 0;

  libhoth_error ret = libhoth_hostcmd_exec_v2(
      dev, HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HOTH_PAYLOAD_UPDATE, 0,
      &request, sizeof(request), NULL, 0, NULL);
  if (ret != HOTH_SUCCESS) {
    fprintf(stderr, "Error code from hoth: 0x%016llx\n",
            (unsigned long long)ret);
    return ret;
  }
  return HOTH_SUCCESS;
}

static libhoth_error get_payload_update_version(struct libhoth_device* dev,
                                                uint8_t* version) {
  uint32_t version_mask = 0;
  const libhoth_error err = libhoth_get_command_versions(
      dev, HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HOTH_PAYLOAD_UPDATE,
      &version_mask);
  const bool get_version_unsupported =
      (err == LIBHOTH_ERR_CONSTRUCT(HOTH_CTX_CMD_EXEC, HOTH_HOST_SPACE_EC,
                                    HOTH_RES_INVALID_COMMAND));
  const bool is_version_0 = (err == HOTH_SUCCESS && (version_mask & 0x2) == 0);
  if (get_version_unsupported || is_version_0) {
    *version = 0;
    return HOTH_SUCCESS;
  }
  if (err != HOTH_SUCCESS) {
    return err;
  }
  *version = 1;
  return HOTH_SUCCESS;
}

static libhoth_error libhoth_payload_update_finalize(
    struct libhoth_device* dev, uint8_t* pld_needs_reinitialization) {
  uint8_t version;
  libhoth_error status = get_payload_update_version(dev, &version);

  if (status != HOTH_SUCCESS) {
    fprintf(
        stderr,
        "Checking supported command version got unexpected error: 0x%016llx\n",
        (unsigned long long)status);
    return status;
  }

  if (version == 0) {
    fprintf(stderr, "Using payload update version 0\n");
    if (pld_needs_reinitialization != NULL) {
      *pld_needs_reinitialization = 0;
    }
    return send_payload_update_request_with_command(dev,
                                                    PAYLOAD_UPDATE_FINALIZE);
  }
  fprintf(stderr, "Using payload update version 1\n");
  struct payload_update_packet request = {
      .type = PAYLOAD_UPDATE_FINALIZE,
  };
  struct payload_update_finalize_response_v1 response = {0};
  status = libhoth_hostcmd_exec_v2(
      dev, HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HOTH_PAYLOAD_UPDATE,
      /*version=*/1, &request, sizeof(request), &response, sizeof(response),
      NULL);
  if (status != HOTH_SUCCESS) {
    return status;
  }
  if (pld_needs_reinitialization != NULL) {
    *pld_needs_reinitialization = response.pld_needs_reinitialization;
  }
  return HOTH_SUCCESS;
}

static libhoth_error payload_update_erase_chunk(
    struct libhoth_device* const dev, const uint32_t offset,
    const uint32_t len) {
  struct payload_update_packet request;
  request.type = PAYLOAD_UPDATE_ERASE;
  request.offset = offset;
  request.len = len;
  return libhoth_hostcmd_exec_v2(
      dev, HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HOTH_PAYLOAD_UPDATE, 0,
      &request, sizeof(request), NULL, 0, NULL);
}

libhoth_error libhoth_payload_update_erase(struct libhoth_device* const dev,
                                           const uint32_t offset,
                                           const uint32_t len) {
  struct libhoth_progress_stderr erase_progress;
  libhoth_progress_stderr_init(&erase_progress, "Erase staging side");

  const size_t block_erase = 64 * 1024;
  const size_t sector_erase = 4 * 1024;

  if (len == 0 || (len % sector_erase) != 0) {
    fprintf(stderr,
            "error: erase length (0x%" PRIx32
            ") is zero or not sector-aligned.\n",
            len);
    return LIBHOTH_ERR_CONSTRUCT(HOTH_CTX_CMD_EXEC, HOTH_HOST_SPACE_LIBHOTH,
                                 LIBHOTH_ERR_INVALID_PARAMETER);
  }
  if ((offset % sector_erase) != 0) {
    fprintf(stderr, "error: offset (0x%" PRIx32 ") is not sector-aligned.\n",
            offset);
    return LIBHOTH_ERR_CONSTRUCT(HOTH_CTX_CMD_EXEC, HOTH_HOST_SPACE_LIBHOTH,
                                 LIBHOTH_ERR_INVALID_PARAMETER);
  }
  if (UINT32_MAX - offset < len) {
    fprintf(stderr,
            "error: invalid erase range (offset 0x%" PRIx32 ", len 0x%" PRIx32
            ")\n",
            offset, len);
    return LIBHOTH_ERR_CONSTRUCT(HOTH_CTX_CMD_EXEC, HOTH_HOST_SPACE_LIBHOTH,
                                 LIBHOTH_ERR_INVALID_PARAMETER);
  }

  uint32_t erased = 0;

  while (erased < len) {
    erase_progress.progress.func(erase_progress.progress.param, erased, len);
    const uint32_t current_offset = offset + erased;
    const uint32_t remaining = len - erased;
    const bool send_block_erase =
        (current_offset % block_erase == 0) && (remaining >= block_erase);
    const uint32_t chunk_size = send_block_erase ? block_erase : sector_erase;
    const libhoth_error ret =
        payload_update_erase_chunk(dev, current_offset, chunk_size);
    if (ret != HOTH_SUCCESS) {
      fprintf(stderr,
              "error: erase chunk offset 0x%" PRIx32 " err: 0x%016llx\n",
              current_offset, (unsigned long long)ret);
      return ret;
    }
    erased += chunk_size;
  }

  erase_progress.progress.func(erase_progress.progress.param, len, len);
  return HOTH_SUCCESS;
}

libhoth_error libhoth_payload_update(struct libhoth_device* dev, uint8_t* image,
                                     size_t size, bool skip_erase,
                                     bool binary_file) {
  if (!binary_file && (libhoth_find_image_descriptor(image, size) == NULL)) {
    return LIBHOTH_ERR_CONSTRUCT(HOTH_CTX_CMD_EXEC, HOTH_HOST_SPACE_LIBHOTH,
                                 LIBHOTH_ERR_INVALID_PARAMETER);
  }

  if (!skip_erase) {
    libhoth_error err = libhoth_payload_update_erase(dev, 0, size);
    if (err != HOTH_SUCCESS) {
      return err;
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

    libhoth_error ret = libhoth_hostcmd_exec_v2(
        dev, HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HOTH_PAYLOAD_UPDATE, 0,
        buffer, sizeof(request) + chunk_size, NULL, 0, NULL);
    if (ret != HOTH_SUCCESS) {
      fprintf(stderr, "Error code from hoth: 0x%016llx\n",
              (unsigned long long)ret);
      return ret;
    }

    offset += chunk_size - 1;
  }

  program_progress.progress.func(program_progress.progress.param, size, size);

  // Don't attempt to verify and activate binary file since most likely it will
  // fail (unlike actual payload images which have an image descriptor)
  if (!binary_file) {
    fprintf(stderr, "Finalizing payload update.\n");
    uint8_t pld_needs_reinitialization = 0;
    libhoth_error finalize_err =
        libhoth_payload_update_finalize(dev, &pld_needs_reinitialization);
    if (finalize_err != HOTH_SUCCESS) {
      return finalize_err;
    }
    if (pld_needs_reinitialization != 0) {
      fprintf(stderr, "PLD updated. Re-initialization needed.\n");
    }
  }

  return HOTH_SUCCESS;
}

libhoth_error libhoth_payload_update_getstatus(
    struct libhoth_device* dev, struct payload_update_status* update_status) {
  struct payload_update_packet request;
  request.type = PAYLOAD_UPDATE_GET_STATUS;
  request.offset = 0;
  request.len = 0;

  size_t rlen = 0;
  libhoth_error ret = libhoth_hostcmd_exec_v2(
      dev, HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HOTH_PAYLOAD_UPDATE, 0,
      &request, sizeof(request), update_status, sizeof(*update_status), &rlen);

  if (ret != HOTH_SUCCESS) {
    fprintf(stderr, "HOTH_PAYLOAD_UPDATE_GET_STATUS error code: 0x%016llx\n",
            (unsigned long long)ret);
    return ret;
  }

  if (rlen != sizeof(*update_status)) {
    fprintf(stderr,
            "HOTH_PAYLOAD_UPDATE_GET_STATUS expected exactly %zu response "
            "bytes, got %zu\n",
            sizeof(*update_status), rlen);
    return LIBHOTH_ERR_CONSTRUCT(HOTH_CTX_CMD_EXEC, HOTH_HOST_SPACE_LIBHOTH,
                                 LIBHOTH_ERR_FAIL);
  }

  return HOTH_SUCCESS;
}

libhoth_error libhoth_payload_update_read_chunk(struct libhoth_device* dev,
                                                int fd, size_t len,
                                                size_t offset) {
  const size_t max_chunk_size =
      LIBHOTH_MAILBOX_SIZE - sizeof(struct hoth_host_response);
  uint8_t buffer[LIBHOTH_MAILBOX_SIZE];

  struct payload_update_packet pkt;

  pkt.type = PAYLOAD_UPDATE_READ;

  while (len > 0) {
    size_t chunk_size = (len < max_chunk_size) ? len : max_chunk_size;

    pkt.offset = offset;
    pkt.len = chunk_size;

    libhoth_error ret = libhoth_hostcmd_exec_v2(
        dev, HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HOTH_PAYLOAD_UPDATE, 0,
        &pkt, sizeof(pkt), buffer, chunk_size, NULL);

    if (ret != HOTH_SUCCESS) {
      fprintf(stderr, "Payload read failed, err code: 0x%016llx\n",
              (unsigned long long)ret);
      return ret;
    }

    int write_ret = libhoth_force_write(fd, buffer, chunk_size);
    if (write_ret != 0) {
      fprintf(stderr,
              "Failed to write payload during payload read, err code: %d\n",
              write_ret);
      return LIBHOTH_ERR_CONSTRUCT(HOTH_CTX_CMD_EXEC, HOTH_HOST_SPACE_POSIX,
                                   errno ? errno : EIO);
    }

    len -= chunk_size;
    offset += chunk_size;
  }

  return HOTH_SUCCESS;
}

// Version 0 does not return a response.
static libhoth_error libhoth_payload_update_activate_v0(
    struct libhoth_device* dev,
    struct payload_update_activate_request* request) {
  libhoth_error status = libhoth_hostcmd_exec_v2(
      dev, HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HOTH_PAYLOAD_UPDATE,
      /*version=*/0, request, sizeof(*request), NULL, 0, NULL);
  if (status != HOTH_SUCCESS) {
    fprintf(stderr, "HOTH_PAYLOAD_UPDATE_ACTIVATE v0 error code: 0x%016llx\n",
            (unsigned long long)status);
    return status;
  }
  return HOTH_SUCCESS;
}

// Version 1 returns a response indicating if the PLD needs to be reinitialized.
static libhoth_error libhoth_payload_update_activate_v1(
    struct libhoth_device* dev, struct payload_update_activate_request* request,
    uint8_t* pld_needs_reinitialization) {
  struct payload_update_activate_response_v1 response = {0};
  libhoth_error status = libhoth_hostcmd_exec_v2(
      dev, HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HOTH_PAYLOAD_UPDATE,
      /*version=*/1, request, sizeof(*request), &response, sizeof(response),
      NULL);
  if (status != HOTH_SUCCESS) {
    fprintf(stderr, "HOTH_PAYLOAD_UPDATE_ACTIVATE v1 error code: 0x%016llx\n",
            (unsigned long long)status);
    return status;
  }
  if (pld_needs_reinitialization != NULL) {
    *pld_needs_reinitialization = response.pld_needs_reinitialization;
  }
  return HOTH_SUCCESS;
}

libhoth_error libhoth_payload_update_activate(
    struct libhoth_device* dev, uint8_t half,
    uint8_t* pld_needs_reinitialization) {
  uint8_t version;
  libhoth_error status = get_payload_update_version(dev, &version);
  if (status != HOTH_SUCCESS) {
    fprintf(
        stderr,
        "Checking supported command version got unexpected error: 0x%016llx\n",
        (unsigned long long)status);
    return status;
  }

  struct payload_update_activate_request request = {
      .header.type = PAYLOAD_UPDATE_ACTIVATE,
      .header.offset = 0,
      .header.len = sizeof(struct payload_update_activate),
      .activate.half = half,
      .activate.make_persistent = 1,
  };

  if (version == 0) {
    fprintf(stderr, "Using payload update version 0\n");
    if (pld_needs_reinitialization != NULL) {
      *pld_needs_reinitialization = 0;
    }
    return libhoth_payload_update_activate_v0(dev, &request);
  }
  fprintf(stderr, "Using payload update version 1\n");
  return libhoth_payload_update_activate_v1(dev, &request,
                                            pld_needs_reinitialization);
}

libhoth_error libhoth_payload_update_verify(struct libhoth_device* dev) {
  return send_payload_update_request_with_command(dev, PAYLOAD_UPDATE_VERIFY);
}

libhoth_error libhoth_payload_update_verify_descriptor(
    struct libhoth_device* dev) {
  return send_payload_update_request_with_command(
      dev, PAYLOAD_UPDATE_VERIFY_DESCRIPTOR);
}

libhoth_error libhoth_payload_update_confirm(struct libhoth_device* dev) {
  payload_update_confirm_response_t confirm_response = {0};

  payload_update_confirm_request_t confirm_request = {0};
  confirm_request.op = PAYLOAD_UPDATE_CONFIRM_OP_CONFIRM;

  struct payload_update_packet pkt_header = {
      .type = PAYLOAD_UPDATE_CONFIRM,
      .offset = 0,
      .len = sizeof(confirm_request),
  };

  uint8_t send_buf[sizeof(pkt_header) + sizeof(confirm_request)] = {0};
  memcpy(&send_buf[0], &pkt_header, sizeof(pkt_header));
  memcpy(&send_buf[sizeof(pkt_header)], &confirm_request,
         sizeof(confirm_request));

  libhoth_error ret = libhoth_hostcmd_exec_v2(
      dev, HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HOTH_PAYLOAD_UPDATE, 0,
      send_buf, sizeof(send_buf), &confirm_response, sizeof(confirm_response),
      NULL);
  if (ret != HOTH_SUCCESS) {
    fprintf(stderr, "Payload update confirm failed, err code: 0x%016llx\n",
            (unsigned long long)ret);
    return ret;
  }

  return HOTH_SUCCESS;
}

libhoth_error libhoth_payload_update_confirm_enable(struct libhoth_device* dev,
                                                    bool enable,
                                                    uint32_t timeout_seconds) {
  payload_update_confirm_response_t confirm_response = {0};

  // Initially fill timeout with the set timeout, if enabled
  // Later we will adjust timeout to default if not explicitly defined here
  payload_update_confirm_request_t confirm_request = {0};
  confirm_request.op = enable ? PAYLOAD_UPDATE_CONFIRM_OP_ENABLE_WITH_TIMEOUT
                              : PAYLOAD_UPDATE_CONFIRM_OP_DISABLE;

  confirm_request.timeout = timeout_seconds;

  struct payload_update_packet pkt_header = {
      .type = PAYLOAD_UPDATE_CONFIRM,
      .offset = 0,
      .len = sizeof(confirm_request),
  };

  // timout_seconds of 0 is treated as a special value to use the default
  // timeout value defined in the firmware.
  if (timeout_seconds == 0 && enable == true) {
    confirm_request.op = PAYLOAD_UPDATE_CONFIRM_OP_ENABLE;
  }

  uint8_t send_buf[sizeof(pkt_header) + sizeof(confirm_request)] = {0};
  memcpy(&send_buf[0], &pkt_header, sizeof(pkt_header));
  memcpy(&send_buf[sizeof(pkt_header)], &confirm_request,
         sizeof(confirm_request));

  libhoth_error ret = libhoth_hostcmd_exec_v2(
      dev, HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HOTH_PAYLOAD_UPDATE, 0,
      send_buf, sizeof(send_buf), &confirm_response, sizeof(confirm_response),
      NULL);
  if (ret != HOTH_SUCCESS) {
    fprintf(stderr,
            "Payload update confirm enable failed, err code: 0x%016llx\n",
            (unsigned long long)ret);
    return ret;
  }

  return HOTH_SUCCESS;
}

libhoth_error libhoth_payload_update_confirm_get_staged_timeout(
    struct libhoth_device* dev, payload_update_confirm_response_t* response) {
  payload_update_confirm_request_t confirm_request = {0};
  confirm_request.op = PAYLOAD_UPDATE_CONFIRM_OP_GET_STAGED_TIMEOUT_VALUES;

  struct payload_update_packet pkt_header = {
      .type = PAYLOAD_UPDATE_CONFIRM,
      .offset = 0,
      .len = sizeof(confirm_request),
  };

  uint8_t send_buf[sizeof(pkt_header) + sizeof(confirm_request)] = {0};
  memcpy(&send_buf[0], &pkt_header, sizeof(pkt_header));
  memcpy(&send_buf[sizeof(pkt_header)], &confirm_request,
         sizeof(confirm_request));

  libhoth_error ret = libhoth_hostcmd_exec_v2(
      dev, HOTH_CMD_BOARD_SPECIFIC_BASE + HOTH_PRV_CMD_HOTH_PAYLOAD_UPDATE, 0,
      send_buf, sizeof(send_buf), response, sizeof(*response), NULL);
  if (ret != HOTH_SUCCESS) {
    fprintf(stderr, "Payload update get timeout failed, err code: 0x%016llx\n",
            (unsigned long long)ret);
    return ret;
  }

  return HOTH_SUCCESS;
}
