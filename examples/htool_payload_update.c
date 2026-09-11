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

#include "examples/htool_payload_update.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "examples/htool.h"
#include "examples/htool_cmd.h"
#include "protocol/payload_update.h"
#include "protocol/status.h"

int htool_payload_update(const struct htool_invocation* inv) {
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  const char* image_file;
  if (htool_get_param_string(inv, "source-file", &image_file)) {
    return -1;
  }

  bool skip_erase;
  if (htool_get_param_bool(inv, "skip_erase", &skip_erase)) {
    return -1;
  }

  bool binary_file = false;
  if (htool_get_param_bool(inv, "binary", &binary_file)) {
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

  uint8_t* image = mmap(NULL, statbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (image == MAP_FAILED) {
    fprintf(stderr, "mmap error: %s\n", strerror(errno));
    goto cleanup;
  }

  libhoth_error payload_update_status = libhoth_payload_update(
      dev, image, statbuf.st_size, skip_erase, binary_file);
  if (payload_update_status != HOTH_SUCCESS) {
    htool_report_error("payload_update", payload_update_status);
    retval = -1;
  } else {
    fprintf(stderr, "Payload update finished\n");
    retval = 0;
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

int htool_payload_read(const struct htool_invocation* inv) {
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  const char* dest_file;

  uint32_t start;
  uint32_t length;

  if (htool_get_param_string(inv, "dest-file", &dest_file) ||
      htool_get_param_u32(inv, "start", &start) ||
      htool_get_param_u32(inv, "length", &length)) {
    return -1;
  }

  if (strlen(dest_file) == 0) {
    fprintf(stderr, "dest-file cannot be empty\n");
    return -1;
  }

  if (length == 0) {
    fprintf(stderr, "Must set --length (-n) to something non-zero\n");
    return -1;
  }

  int fd = open(dest_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd == -1) {
    fprintf(stderr, "Error opening file %s: %s\n", dest_file, strerror(errno));
    return -1;
  }

  libhoth_error err = libhoth_payload_update_read_chunk(dev, fd, length, start);

  close(fd);
  if (err != HOTH_SUCCESS) {
    htool_report_error("payload_update read", err);
    return -1;
  }
  return 0;
}

const char* payload_update_getstatus_valid_string(uint8_t v) {
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

const char* payload_update_getstatus_half_string(uint8_t h) {
  switch (h) {
    case 0:
      return "A";
    case 1:
      return "B";
    default:
      return "(unknown)";
  }
}

int htool_payload_update_getstatus(const struct htool_invocation* inv) {
  (void)inv;
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  struct payload_update_status pus;
  libhoth_error err = libhoth_payload_update_getstatus(dev, &pus);

  if (err != HOTH_SUCCESS) {
    htool_report_error("payload_update getstatus", err);
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

int htool_payload_erase(const struct htool_invocation* inv) {
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  uint32_t start;
  uint32_t length;
  if (htool_get_param_u32(inv, "start", &start) ||
      htool_get_param_u32(inv, "length", &length)) {
    return -1;
  }
  libhoth_error err = libhoth_payload_update_erase(dev, start, length);
  if (err != HOTH_SUCCESS) {
    htool_report_error("payload_update erase", err);
    return -1;
  }
  return 0;
}

int htool_payload_activate(const struct htool_invocation* inv) {
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  const char* side_str;
  if (htool_get_param_string(inv, "side", &side_str)) {
    return -1;
  }

  uint8_t half;
  if (strcasecmp(side_str, "A") == 0) {
    half = 0;
  } else if (strcasecmp(side_str, "B") == 0) {
    half = 1;
  } else {
    fprintf(stderr, "Unknown side: %s (expected A or B)\n", side_str);
    return -1;
  }

  uint8_t pld_needs_reinitialization = 0;
  libhoth_error err =
      libhoth_payload_update_activate(dev, half, &pld_needs_reinitialization);
  if (err != HOTH_SUCCESS) {
    htool_report_error("payload_update activate", err);
    return -1;
  }

  printf("PLD needs re-initialization?: %d\n", pld_needs_reinitialization);
  return 0;
}

int htool_payload_update_verify(const struct htool_invocation* inv) {
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  bool verify_only_descriptor = false;
  if (htool_get_param_bool(inv, "descriptor", &verify_only_descriptor)) {
    return -1;
  }
  libhoth_error err;
  if (verify_only_descriptor) {
    err = libhoth_payload_update_verify_descriptor(dev);
  } else {
    fprintf(stderr,
            "Verifying the payload. This can take up to three minutes...\n");
    err = libhoth_payload_update_verify(dev);
  }
  if (err != HOTH_SUCCESS) {
    htool_report_error("payload_update verify", err);
    return -1;
  }
  if (verify_only_descriptor) {
    printf("Payload verify descriptor successful\n");
  } else {
    printf("Payload verify successful\n");
  }
  return 0;
}

int htool_payload_update_confirm(const struct htool_invocation* inv) {
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  libhoth_error err = libhoth_payload_update_confirm(dev);
  if (err != HOTH_SUCCESS) {
    htool_report_error("payload_update confirm", err);
    return -1;
  }

  return 0;
}

int htool_payload_update_confirm_get_staged_timeout(
    const struct htool_invocation* inv) {
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  payload_update_confirm_response_t response = {0};

  libhoth_error err =
      libhoth_payload_update_confirm_get_staged_timeout(dev, &response);
  if (err != HOTH_SUCCESS) {
    htool_report_error("payload_update confirm_get_staged_timeout", err);
    return -1;
  }

  printf("Current timeout: %u seconds\n", response.timeouts.current);
  printf("Current MIN timeout: %u seconds\n", response.timeouts.min);
  printf("Current MAX timeout: %u seconds\n", response.timeouts.max);
  printf("Current default timeout: %u seconds\n",
         response.timeouts.default_val);

  return 0;
}

int htool_payload_update_confirm_enable(const struct htool_invocation* inv) {
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  uint32_t timeout = 0;
  if (htool_get_param_u32(inv, "timeout", &timeout)) {
    return -1;
  }

  bool enable_confirm = true;
  if (htool_get_param_bool(inv, "enable", &enable_confirm)) {
    return -1;
  }

  libhoth_error err =
      libhoth_payload_update_confirm_enable(dev, enable_confirm, timeout);
  if (err != HOTH_SUCCESS) {
    htool_report_error("payload_update confirm_enable", err);
    return -1;
  }

  return 0;
}
