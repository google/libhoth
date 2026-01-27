// Copyright 2023 Google LLC
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

#include "htool_payload.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "host_commands.h"
#include "htool.h"
#include "protocol/payload_info.h"
#include "protocol/payload_status.h"

int htool_payload_status(const struct htool_invocation* inv) {
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  struct payload_status ps;
  int ret = libhoth_payload_status(dev, &ps);
  if (ret != 0) {
    fprintf(stderr, "HOTH_PAYLOAD_STATUS error code: %d\n", ret);
    return -1;
  }

  struct payload_status_response_header* ppsr = &ps.resp_hdr;

  printf("lockdown_state: %s (%u)\n",
         libhoth_sps_eeprom_lockdown_status_string(ppsr->lockdown_state),
         ppsr->lockdown_state);
  printf("active_half   : %c\n", ppsr->active_half ? 'B' : 'A');

  for (int region_index = 0; region_index < ppsr->region_count;
       region_index++) {
    const struct payload_region_state* rs = &ps.region_state[region_index];

    printf("Region %c:\n", region_index == 0 ? 'A' : 'B');
    printf("  validation_state: %s (%u)\n",
           libhoth_payload_validation_state_string(rs->validation_state),
           rs->validation_state);
    if (rs->validation_state == PAYLOAD_IMAGE_UNVERIFIED) {
      // The rest of the fields won't have meaningful values.
      continue;
    }
    if (rs->failure_reason) {
      printf(
          "  failure_reason: %s (%u)\n",
          libhoth_payload_validation_failure_reason_string(rs->failure_reason),
          rs->failure_reason);
    }
    printf("  image_type: %s (%u)\n", libhoth_image_type_string(rs->image_type),
           rs->image_type);
    printf("  image_family: (0x%08x)\n", rs->image_family);
    printf("  version: %u.%u.%u.%u\n", rs->version_major, rs->version_minor,
           rs->version_point, rs->version_subpoint);
    printf("  descriptor_offset: 0x%08x\n", rs->descriptor_offset);
  }
  return 0;
}

int htool_payload_info(const struct htool_invocation* inv) {
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  const char* image_file;
  if (htool_get_param_string(inv, "source-file", &image_file) != 0) {
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

  uint8_t* image = mmap(NULL, statbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (image == MAP_FAILED) {
    fprintf(stderr, "mmap error: %s\n", strerror(errno));
    goto cleanup2;
  }

  struct payload_info info;
  if (!libhoth_payload_info(image, statbuf.st_size, &info)) {
    fprintf(stderr, "Failed to parse payload image.  Is this a titan image?\n");
    goto cleanup;
  }

  printf("Payload Info:\n");
  printf("  name: %-32s\n", info.image_name);
  printf("  family: %u\n", info.image_family);
  printf("  version: %u.%u.%u.%u\n", info.image_version.major,
         info.image_version.minor, info.image_version.point,
         info.image_version.subpoint);
  printf("  type: %u\n", info.image_type);
  printf("  hash: ");
  for (int i = 0; i < sizeof(info.image_hash); i++) {
    printf("%02x", info.image_hash[i]);
  }
  printf("\n");

cleanup:
  if (munmap(image, statbuf.st_size) != 0) {
    fprintf(stderr, "munmap error: %s\n", strerror(errno));
    return -1;
  }

cleanup2:
  if (close(fd) != 0) {
    fprintf(stderr, "close error: %s\n", strerror(errno));
    return -1;
  }

  return 0;
}
