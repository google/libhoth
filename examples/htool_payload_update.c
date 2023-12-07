// Copyright 2022 Google LLC
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

#include "htool_payload_update.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "host_commands.h"
#include "htool.h"
#include "htool_cmd.h"

const int64_t TITAN_IMAGE_DESCRIPTOR_MAGIC = 0x5F435344474D495F;
const int64_t TITAN_IMAGE_DESCRIPTOR_ALIGNMENT = 1 << 16;

bool find_image_descriptor(uint8_t *image, size_t len, size_t offset_alignment,
                           int64_t magic) {
  for (size_t offset = 0; offset + sizeof(int64_t) - 1 < len;
       offset += offset_alignment) {
    int64_t magic_candidate;
    memcpy(&magic_candidate, image + offset, sizeof(int64_t));
    if (magic_candidate == magic) {
      return true;
    }
  }
  return false;
}

int send_payload_update_request_with_command(struct libhoth_device *dev,
                                             uint8_t command) {
  struct payload_update_packet request;
  request.type = command;
  request.offset = 0;
  request.len = 0;

  int ret = htool_exec_hostcmd(
      dev, EC_CMD_BOARD_SPECIFIC_BASE + EC_PRV_CMD_HOTH_PAYLOAD_UPDATE, 0,
      &request, sizeof(request), NULL, 0, NULL);
  if (ret != 0) {
    fprintf(stderr, "Error code from hoth: %d\n", ret);
    return -1;
  }
  return 0;
}

int send_image(struct libhoth_device *dev, const uint8_t *image, size_t size) {
  const size_t max_chunk_size = MAILBOX_SIZE - sizeof(struct ec_host_request) -
                                sizeof(struct payload_update_packet);

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

    uint8_t buffer[sizeof(struct payload_update_packet) + MAILBOX_SIZE];
    memcpy(buffer, &request, sizeof(request));
    memcpy(buffer + sizeof(request), image + offset, chunk_size);

    int ret = htool_exec_hostcmd(
        dev, EC_CMD_BOARD_SPECIFIC_BASE | EC_PRV_CMD_HOTH_PAYLOAD_UPDATE, 0,
        buffer, sizeof(request) + chunk_size, NULL, 0, NULL);
    if (ret != 0) {
      fprintf(stderr, "Error code from hoth: %d\n", ret);
      return -1;
    }

    offset += chunk_size - 1;
  }
  return 0;
}

int htool_payload_update(const struct htool_invocation *inv) {
  struct libhoth_device *dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  const char *image_file;
  if (htool_get_param_string(inv, "source-file", &image_file)) {
    return -1;
  }

  int fd = open(image_file, O_RDONLY, 0);
  if (fd == -1) {
    fprintf(stderr, "Error opening file %s: %s\n", image_file, strerror(errno));
    return -1;
  }
  struct stat statbuf;
  if (fstat(fd, &statbuf)) {
    fprintf(stderr, "fstat error: %s\n", strerror(errno));
    goto cleanup2;
  }
  if (statbuf.st_size > SIZE_MAX) {
    fprintf(stderr, "file too large\n");
    goto cleanup2;
  }

  uint8_t *image = mmap(NULL, statbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (image == MAP_FAILED) {
    fprintf(stderr, "mmap error: %s\n", strerror(errno));
    goto cleanup2;
  }

  if (!find_image_descriptor(image, statbuf.st_size,
                             TITAN_IMAGE_DESCRIPTOR_ALIGNMENT,
                             TITAN_IMAGE_DESCRIPTOR_MAGIC)) {
    fprintf(stderr, "Not a valid Titan image.\n");
    goto cleanup;
  }

  // Hoth payload update protocol.

  // Send initiate.
  fprintf(stderr, "Initiating payload update protocol with hoth.\n");
  int ret =
      send_payload_update_request_with_command(dev, PAYLOAD_UPDATE_INITIATE);
  if (ret != 0) {
    fprintf(stderr, "Error when initiating payload update.\n");
    goto cleanup;
  }

  // Send continue.
  fprintf(stderr, "Flashing the image to hoth.\n");
  ret = send_image(dev, image, statbuf.st_size);
  if (ret != 0) {
    fprintf(stderr, "Error when flashing.\n");
    goto cleanup;
  }

  // Send finalize.
  fprintf(stderr, "Finalizing payload update.\n");
  ret = send_payload_update_request_with_command(dev, PAYLOAD_UPDATE_FINALIZE);
  if (ret != 0) {
    fprintf(stderr, "Error when finalizing.\n");
    goto cleanup;
  }

  return 0;

cleanup:
  ret = munmap(image, statbuf.st_size);
  if (ret != 0) {
    fprintf(stderr, "munmap error: %d\n", ret);
  }

cleanup2:
  ret = close(fd);
  if (ret != 0) {
    fprintf(stderr, "close error: %d\n", ret);
  }
  return -1;
}