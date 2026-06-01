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

#include "htool_mauv.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "htool.h"
#include "protocol/mauv.h"

static void print_firmware_mauv(const struct hoth_response_mauv* mauv) {
  printf("Firmware MAUV:\n");
  printf("  Struct Version: %u\n", mauv->haven.struct_version);
  printf("  MAUV Version:   %u\n", mauv->haven.mauv_version);
  printf("  Minimum Version: %u.%u.%lu\n",
         mauv->haven.minimum_acceptable_update_version.epoch,
         mauv->haven.minimum_acceptable_update_version.major,
         mauv->haven.minimum_acceptable_update_version.minor);
  printf("  Denylist (%u entries):\n", mauv->haven.denylist_num_entries);
  for (uint32_t i = 0;
       i < mauv->haven.denylist_num_entries && i < HAVEN_MAUV_MAX_DENYLIST_SIZE;
       i++) {
    printf("    [%u]: %u.%u.%lu\n", i, mauv->haven.denylist[i].epoch,
           mauv->haven.denylist[i].major, mauv->haven.denylist[i].minor);
  }
}

int htool_mauv_compiled(const struct htool_invocation* inv) {
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  struct hoth_response_mauv mauv;
  libhoth_error err =
      libhoth_fetch_mauv(dev, MAUV_STATE_COMPILED, HAVEN_MAUV, &mauv);
  if (err != HOTH_SUCCESS) {
    htool_report_error("fetch_mauv", err);
    return -1;
  }

  print_firmware_mauv(&mauv);
  return 0;
}

int htool_mauv_effective(const struct htool_invocation* inv) {
  // TODO: support FW MAUV effective once it's implemented in firmware.
  return 0;
}

int htool_mauv_update(const struct htool_invocation* inv) {
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  const char* record_file;
  if (htool_get_param_string(inv, "record-file", &record_file)) {
    return -1;
  }

  int fd = open(record_file, O_RDONLY);
  if (fd == -1) {
    fprintf(stderr, "Error opening file %s: %s\n", record_file,
            strerror(errno));
    return -1;
  }

  struct stat statbuf;
  if (fstat(fd, &statbuf)) {
    fprintf(stderr, "fstat error: %s\n", strerror(errno));
    close(fd);
    return -1;
  }

  if (statbuf.st_size > MAUV_MAX_RECORD_SIZE) {
    fprintf(stderr,
            "Error: MAUV record file is too large (%ld bytes, max %d)\n",
            statbuf.st_size, MAUV_MAX_RECORD_SIZE);
    close(fd);
    return -1;
  }

  uint8_t* record_data = malloc(statbuf.st_size);
  if (!record_data) {
    fprintf(stderr, "Memory allocation failed\n");
    close(fd);
    return -1;
  }

  ssize_t bytes_read = read(fd, record_data, statbuf.st_size);
  if (bytes_read != statbuf.st_size) {
    fprintf(stderr, "Error reading file: %s\n", strerror(errno));
    free(record_data);
    close(fd);
    return -1;
  }
  close(fd);

  printf("Sending MAUV update record (%zd bytes)...\n", bytes_read);
  libhoth_error err = libhoth_update_mauv(dev, record_data, bytes_read);
  free(record_data);

  if (err != HOTH_SUCCESS) {
    htool_report_error("update_mauv", err);
    return -1;
  }

  printf("MAUV update successful!\n");
  return 0;
}
