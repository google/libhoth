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

#include "htool_dfu.h"

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
#include "protocol/dfu_check.h"
#include "protocol/dfu_hostcmd.h"
#include "protocol/opentitan_version.h"

int htool_dfu_update(const struct htool_invocation* inv) {
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  struct opentitan_image_version desired_rom_ext = {0};
  struct opentitan_image_version desired_app = {0};
  struct opentitan_get_version_resp resp = {0};

  uint32_t complete_flags = 0;
  const char* reset_arg;
  if (htool_get_param_string(inv, "reset", &reset_arg)) {
    return -1;
  }
  if (strcmp(reset_arg, "warm") == 0) {
    complete_flags |= HOTH_DFU_COMPLETE_FLAGS_WARM_RESTART;
  } else if (strcmp(reset_arg, "cold") == 0) {
    complete_flags |= HOTH_DFU_COMPLETE_FLAGS_COLD_RESTART;
  } else if (strcmp(reset_arg, "none") == 0) {
    // No flags needed
  } else {
    fprintf(
        stderr,
        "Invalid value for --reset: %s. Must be 'warm', 'cold', or 'none'.\n",
        reset_arg);
    return -1;
  }

  const char* fwupdate_file;
  if (htool_get_param_string(inv, "fwupdate-file", &fwupdate_file)) {
    return -1;
  }

  int fd = open(fwupdate_file, O_RDONLY, 0);
  if (fd == -1) {
    fprintf(stderr, "Error opening file %s: %s\n", fwupdate_file,
            strerror(errno));
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

  // Populate rom_ext and app with the desired extracted versions from the image
  retval = libhoth_extract_ot_bundle(image, statbuf.st_size, &desired_rom_ext,
                                     &desired_app);

  if (retval != 0) {
    fprintf(stderr, "Failed to extract bundle\n");
    goto cleanup2;
  }

  // Get the current version of the device
  retval = libhoth_opentitan_version(dev, &resp);

  if (retval != 0) {
    fprintf(stderr, "Failed to get current version\n");
    goto cleanup2;
  }

  // Determine the stage slot for each ot get version to compare
  uint32_t rom_ext_boot_slot = bootslot_int(resp.rom_ext.booted_slot);
  uint32_t rom_ext_stage_slot = rom_ext_boot_slot == 0 ? 1 : 0;
  uint32_t app_boot_slot = bootslot_int(resp.app.booted_slot);
  uint32_t app_stage_slot = app_boot_slot == 0 ? 1 : 0;

  // Compare the desired version with the current bootslot version
  // If they are different, we need to automatically perform the x2 update
  // If both are the same & the staged slot is different, we need to perform a
  // single update For all other cases, no update is needed
  if (libhoth_ot_version_eq(&resp.rom_ext.slots[rom_ext_boot_slot],
                            &desired_rom_ext) == false ||
      libhoth_ot_version_eq(&resp.app.slots[app_boot_slot], &desired_app) ==
          false) {
    printf(
        "The current bootslot is not the desired version. Performing DFU "
        "update x2...\n");
    // Peform the DFU update twice to update both slots
    // First update will stage to the non-booted slot, second update correct the
    // newly staged slot.
    for (int i = 0; i < 2; i++) {
      retval = libhoth_dfu_update(dev, image, statbuf.st_size, complete_flags);

      if (retval != 0) {
        fprintf(stderr, "DFU update failed\n");
        goto cleanup2;
      }
    }
  } else {
    if (libhoth_ot_version_eq(&resp.rom_ext.slots[rom_ext_stage_slot],
                              &desired_rom_ext) == false ||
        libhoth_ot_version_eq(&resp.app.slots[app_stage_slot], &desired_app) ==
            false) {
      printf(
          "The staged slot is not the desired version. Performing DFU update "
          "x1...\n");
      // Perform a single DFU update to update the staged slot
      retval = libhoth_dfu_update(dev, image, statbuf.st_size, complete_flags);

      if (retval != 0) {
        fprintf(stderr, "DFU update failed\n");
        goto cleanup2;
      }
    } else {
      printf(
          "Device is already at the desired version. No DFU update needed.\n");
    }
  }

  int ret;

cleanup2:
  ret = munmap(image, statbuf.st_size);
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

int htool_dfu_check(const struct htool_invocation* inv) {
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  struct opentitan_get_version_resp resp = {0};

  const char* fwupdate_file;
  if (htool_get_param_string(inv, "fwupdate-file", &fwupdate_file)) {
    return -1;
  }

  int fd = open(fwupdate_file, O_RDONLY, 0);
  if (fd == -1) {
    fprintf(stderr, "Error opening file %s: %s\n", fwupdate_file,
            strerror(errno));
    return -1;
  }

  int retval = -1;

  struct stat statbuf;
  if (fstat(fd, &statbuf)) {
    fprintf(stderr, "error: fstat error: %s\n", strerror(errno));
    goto cleanup;
  }
  if (statbuf.st_size > SIZE_MAX) {
    fprintf(stderr, "error: file too large \n");
    goto cleanup;
  }

  uint8_t* image = mmap(NULL, statbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (image == MAP_FAILED) {
    fprintf(stderr, "error: mmap error: %s\n", strerror(errno));
    goto cleanup;
  }

  if (libhoth_opentitan_version(dev, &resp) != 0) {
    fprintf(stderr, "error: Failed to get current version\n");
    goto cleanup2;
  }

  if (libhoth_dfu_check(dev, image, statbuf.st_size, &resp) != 0) {
    fprintf(stderr, "error: DFU check failed.\n");
    goto cleanup2;
  }

  retval = 0;

  int ret;
cleanup2:
  ret = munmap(image, statbuf.st_size);
  if (ret != 0) {
    fprintf(stderr, "error: munmap error: %d\n", ret);
  }

cleanup:
  ret = close(fd);
  if (ret != 0) {
    fprintf(stderr, "error: close error: %d\n", ret);
  }
  return retval;
}
