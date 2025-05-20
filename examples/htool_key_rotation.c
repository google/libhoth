// Copyright 2025 Google LLC

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     https://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.guage governing permissions and
// limitations under the License.

#include "htool_key_rotation.h"

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "htool.h"
#include "protocol/key_rotation.h"

static const char *get_validation_method_string(uint32_t validation_method) {
  switch (validation_method) {
    case 1:
      return "Embedded Key";
    case 2:
      return "Payload Key";
    case 3:
      return "Hash";
    default:
      return "Unknown";
  }
}

int htool_key_rotation_get_status() {
  struct libhoth_device *dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }
  struct hoth_response_key_rotation_status status;
  int ret = libhoth_key_rotation_get_status(dev, &status);
  if (ret != 0) {
    fprintf(stderr, "Failed to get key rotation status\n");
    return -1;
  }

  printf("version        : %u\n", status.version);
  printf("image_family   : %u\n", status.image_family);
  printf("image_family_variant   : %u\n", status.image_family_variant);
  printf("validation_method   : %s\n", get_validation_method_string(status.validation_method));
  printf("validation_key_data   : %x\n", status.validation_key_data);
  printf("validation_hash_data   : %x\n", status.validation_hash_data);
  return 0;
}

int htool_key_rotation_get_version() {
  struct libhoth_device *dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }
  struct hoth_response_key_rotation_record_version version;
  int ret = libhoth_key_rotation_get_version(dev, &version);
  if (ret != 0) {
    fprintf(stderr, "Failed to get key rotation version\n");
    return -1;
  }
  printf("version        : %u\n", version.version);
  return 0;
}

int htool_key_rotation_payload_status() {
  struct libhoth_device *dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }
  struct hoth_response_key_rotation_payload_status payload_status;
  int ret = libhoth_key_rotation_payload_status(dev, &payload_status);
  if (ret != 0) {
    fprintf(stderr, "Failed to get key rotation payload status\n");
    return -1;
  }
  printf("validation_method   : %u\n", payload_status.validation_method);
  printf("validation_key_data   : %u\n", payload_status.validation_key_data);
  printf("validation_hash_data   : %u\n", payload_status.validation_hash_data);
  return 0;
}
