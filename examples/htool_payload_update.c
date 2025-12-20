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
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "htool.h"
#include "htool_cmd.h"
#include "protocol/payload_update.h"

int htool_payload_update(const struct htool_invocation *inv) {
  struct libhoth_device *dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  const char *image_file;
  if (htool_get_param_string(inv, "source-file", &image_file)) {
    return -1;
  }

  bool skip_erase;
  if (htool_get_param_bool(inv, "skip_erase", &skip_erase)) {
    return -1;
  }

  int fd = open(image_file, O_RDONLY, 0);
  if (fd == -1) {
    fprintf(stderr, "Error opening file %s: %s\n", image_file, strerror(errno));
    return -1;
  }

  int retval = -1;

  struct stat statbuf;
  if (fstat(fd, &statbuf)) {
    fprintf(stderr, "fstat error: %s\n", strerror(errno));
    goto cleanup;
  }
  if (statbuf.st_size > SIZE_MAX) {
    fprintf(stderr, "file too large\n");
    goto cleanup;
  }

  uint8_t *image = mmap(NULL, statbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (image == MAP_FAILED) {
    fprintf(stderr, "mmap error: %s\n", strerror(errno));
    goto cleanup;
  }

  enum payload_update_err payload_update_status =
      libhoth_payload_update(dev, image, statbuf.st_size, skip_erase);
  switch (payload_update_status) {
    case PAYLOAD_UPDATE_OK:
      fprintf(stderr, "Payload update finished\n");
      retval = 0;
      break;
    case PAYLOAD_UPDATE_BAD_IMG:
      fprintf(stderr, "Not a valid Titan image.\n");
      break;
    case PAYLOAD_UPDATE_INITIATE_FAIL:
      fprintf(stderr, "Error when initiating payload update.\n");
      break;
    case PAYLOAD_UPDATE_FLASH_FAIL:
      fprintf(stderr, "Error when flashing.\n");
      break;
    case PAYLOAD_UPDATE_FINALIZE_FAIL:
      fprintf(stderr, "Error when finalizing.\n");
      break;
    default:
      break;
  }

  int ret = munmap(image, statbuf.st_size);
  if (ret != 0) {
    fprintf(stderr, "munmap error: %d\n", ret);
  }

cleanup:
  ret = close(fd);
  if (ret != 0) {
    fprintf(stderr, "close error: %d\n", ret);
  }
  return retval;
}

const char *payload_update_getstatus_valid_string(uint8_t v) {
  switch (v) {
    case 0:
      return "Invalid";
    case 1:
      return "Unverified";
    case 2:
      return "Valid";
    case 3:
      return "Descriptor Valid";
    default:
      return "(unknown)";
  }
}

const char *payload_update_getstatus_half_string(uint8_t h) {
  switch (h) {
    case 0:
      return "A";
    case 1:
      return "B";
    default:
      return "(unknown)";
  }
}

int htool_payload_update_getstatus() {
  struct libhoth_device *dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  struct payload_update_status pus;
  int ret = libhoth_payload_update_getstatus(dev, &pus);

  if (ret != 0) {
    fprintf(stderr, "Failed to get payload update status\n");
    return -1;
  }

  printf("a_valid        : %s (%u)\n",
         payload_update_getstatus_valid_string(pus.a_valid), pus.a_valid);
  printf("b_valid        : %s (%u)\n",
         payload_update_getstatus_valid_string(pus.b_valid), pus.b_valid);
  printf("active_half    : %s (%u)\n",
         payload_update_getstatus_half_string(pus.active_half),
         pus.active_half);
  printf("next_half      : %s (%u)\n",
         payload_update_getstatus_half_string(pus.next_half), pus.next_half);
  printf("persistent_half: %s (%u)\n",
         payload_update_getstatus_half_string(pus.persistent_half),
         pus.persistent_half);

  return 0;
}
