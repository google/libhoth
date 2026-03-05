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
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "host_commands.h"
#include "htool.h"
#include "protocol/payload_info.h"
#include "protocol/payload_status.h"

static void print_region_attributes(uint16_t attributes) {
  static const struct {
    uint16_t mask;
    const char* name;
  } flags[] = {
      {IMAGE_REGION_STATIC, "STATIC"},
      {IMAGE_REGION_COMPRESSED, "COMPRESSED"},
      {IMAGE_REGION_WRITE_PROTECTED, "WRITE_PROTECTED"},
      {IMAGE_REGION_PERSISTENT, "PERSISTENT"},
      {IMAGE_REGION_PERSISTENT_RELOCATABLE, "PERSISTENT_RELOCATABLE"},
      {IMAGE_REGION_PERSISTENT_EXPANDABLE, "PERSISTENT_EXPANDABLE"},
      {IMAGE_REGION_OVERRIDE, "OVERRIDE"},
      {IMAGE_REGION_OVERRIDE_ON_TRANSITION, "OVERRIDE_ON_TRANSITION"},
      {IMAGE_REGION_MAILBOX, "MAILBOX"},
      {IMAGE_REGION_SKIP_BOOT_VALIDATION, "SKIP_BOOT_VALIDATION"},
      {IMAGE_REGION_EMPTY, "EMPTY"},
  };

  printf("0x%04x", attributes);
  bool first = true;
  for (size_t i = 0; i < sizeof(flags) / sizeof(flags[0]); i++) {
    if (attributes & flags[i].mask) {
      printf("%s%s", first ? " (" : " | ", flags[i].name);
      first = false;
    }
  }
  if (!first) {
    printf(")");
  }
  printf("\n");
}

static void print_regions(const struct payload_info_all* info_all,
                          uint16_t skip_mask) {
  for (uint8_t i = 0; i < info_all->region_count; i++) {
    const struct payload_region_info* r = &info_all->regions[i];
    if (r->region_attributes & skip_mask) {
      continue;
    }
    printf("  Region %u:\n", i);
    printf("    name: %s\n", r->region_name);
    printf("    offset: 0x%08x\n", r->region_offset);
    printf("    size: 0x%08x\n", r->region_size);
    printf("    version: %u\n", r->region_version);
    printf("    attributes: ");
    print_region_attributes(r->region_attributes);
  }
}

static const char* hash_type_string(uint8_t hash_type) {
  switch (hash_type) {
    case HASH_NONE:
      return "None";
    case HASH_SHA2_256:
      return "SHA2-256";
    default:
      return "Unknown";
  }
}

struct htool_payload_image {
  uint8_t* image;
  size_t size;
  int fd;
};

static int htool_payload_image_open(const struct htool_invocation* inv,
                                    struct htool_payload_image* img) {
  const char* image_file;
  if (htool_get_param_string(inv, "source-file", &image_file) != 0) {
    return -1;
  }
  img->fd = open(image_file, O_RDONLY, 0);
  if (img->fd == -1) {
    fprintf(stderr, "Error opening file %s: %s\n", image_file, strerror(errno));
    return -1;
  }
  struct stat statbuf;
  if (fstat(img->fd, &statbuf)) {
    fprintf(stderr, "fstat error: %s\n", strerror(errno));
    close(img->fd);
    return -1;
  }
  if (statbuf.st_size > SIZE_MAX) {
    fprintf(stderr, "file too large\n");
    close(img->fd);
    return -1;
  }
  img->size = (size_t)statbuf.st_size;
  img->image = mmap(NULL, img->size, PROT_READ, MAP_PRIVATE, img->fd, 0);
  if (img->image == MAP_FAILED) {
    fprintf(stderr, "mmap error: %s\n", strerror(errno));
    close(img->fd);
    return -1;
  }
  return 0;
}

static int htool_payload_image_close(struct htool_payload_image* img) {
  int rv = 0;
  if (munmap(img->image, img->size) != 0) {
    fprintf(stderr, "munmap error: %s\n", strerror(errno));
    rv = -1;
  }
  if (close(img->fd) != 0) {
    fprintf(stderr, "close error: %s\n", strerror(errno));
    rv = -1;
  }
  return rv;
}

int htool_payload_status(const struct htool_invocation* inv) {
  (void)inv;
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
  struct htool_payload_image img;
  if (htool_payload_image_open(inv, &img) != 0) {
    return -1;
  }

  struct payload_info info;
  if (!libhoth_payload_info(img.image, img.size, &info)) {
    fprintf(stderr, "Failed to parse payload image.  Is this a titan image?\n");
    return htool_payload_image_close(&img);
  }

  printf("Payload Info:\n");
  printf("  name: %-32s\n", info.image_name);
  printf("  family: %u\n", info.image_family);
  printf("  version: %u.%u.%u.%u\n", info.image_version.major,
         info.image_version.minor, info.image_version.point,
         info.image_version.subpoint);
  printf("  type: %u\n", info.image_type);
  printf("  hash: ");
  for (size_t i = 0; i < sizeof(info.image_hash); i++) {
    printf("%02x", info.image_hash[i]);
  }
  printf("\n");

  return htool_payload_image_close(&img);
}

int htool_payload_info_all(const struct htool_invocation* inv) {
  struct htool_payload_image img;
  if (htool_payload_image_open(inv, &img) != 0) {
    return -1;
  }

  struct payload_info_all info_all;
  if (!libhoth_payload_info_all(img.image, img.size, &info_all)) {
    fprintf(stderr, "Failed to parse payload image.  Is this a titan image?\n");
    return htool_payload_image_close(&img);
  }

  printf("Payload Info All:\n");
  printf("  name: %-32s\n", info_all.info.image_name);
  printf("  family: %u\n", info_all.info.image_family);
  printf("  version: %u.%u.%u.%u\n", info_all.info.image_version.major,
         info_all.info.image_version.minor, info_all.info.image_version.point,
         info_all.info.image_version.subpoint);
  printf("  type: %u (%s)\n", info_all.info.image_type,
         libhoth_image_type_string(info_all.info.image_type));
  printf("  hash_type: %u (%s)\n", info_all.hash_type,
         hash_type_string(info_all.hash_type));
  printf("  hash: ");
  for (size_t i = 0; i < sizeof(info_all.info.image_hash); i++) {
    printf("%02x", info_all.info.image_hash[i]);
  }
  printf("\n");
  printf("  descriptor_version: %u.%u\n", info_all.descriptor_major,
         info_all.descriptor_minor);
  printf("  build_timestamp: %" PRIu64, info_all.build_timestamp);
#if __SIZEOF_POINTER__ >= 8
  if (info_all.build_timestamp != 0) {
    time_t t = (time_t)info_all.build_timestamp;
    struct tm tm;
    if (gmtime_r(&t, &tm)) {
      char buf[64];
      if (strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S UTC", &tm) > 0) {
        printf(" (%s)", buf);
      }
    }
  }
#endif
  printf("\n");
  printf("  image_size: 0x%08x\n", info_all.image_size);
  printf("  blob_size: %u\n", info_all.blob_size);
  printf("  region_count: %u\n", info_all.region_count);

  print_regions(&info_all, /*skip_mask=*/0);

  return htool_payload_image_close(&img);
}

int htool_payload_info_nonstatic(const struct htool_invocation* inv) {
  struct htool_payload_image img;
  if (htool_payload_image_open(inv, &img) != 0) {
    return -1;
  }

  struct payload_info_all info_all;
  if (!libhoth_payload_info_all(img.image, img.size, &info_all)) {
    fprintf(stderr, "Failed to parse payload image.  Is this a titan image?\n");
    return htool_payload_image_close(&img);
  }

  printf("Non-static regions:\n");
  print_regions(&info_all, /*skip_mask=*/IMAGE_REGION_STATIC);

  return htool_payload_image_close(&img);
}