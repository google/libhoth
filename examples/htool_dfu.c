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

static int dfu_update_count(struct opentitan_image_version* desired_romext,
                            struct opentitan_image_version* desired_app,
                            struct opentitan_get_version_resp* resp) {
  // Determine the stage slot for each ot get version to compare
  uint32_t rom_ext_boot_slot = bootslot_int(resp->rom_ext.booted_slot);
  uint32_t rom_ext_stage_slot = rom_ext_boot_slot == 0 ? 1 : 0;
  uint32_t app_boot_slot = bootslot_int(resp->app.booted_slot);
  uint32_t app_stage_slot = app_boot_slot == 0 ? 1 : 0;

  struct opentitan_image_version* booted_romext =
      &resp->rom_ext.slots[rom_ext_boot_slot];
  struct opentitan_image_version* staged_romext =
      &resp->rom_ext.slots[rom_ext_stage_slot];
  struct opentitan_image_version* booted_app = &resp->app.slots[app_boot_slot];
  struct opentitan_image_version* staged_app = &resp->app.slots[app_stage_slot];

  bool booted_needs_update =
      !libhoth_ot_version_eq(booted_app, desired_app) ||
      !libhoth_ot_version_eq(booted_romext, desired_romext);

  if (booted_needs_update) {
    printf(
        "The current bootslot is not the desired version. Performing DFU "
        "update x2...\n");
    return 2;
  }

  bool staging_needs_update =
      !libhoth_ot_version_eq(staged_app, desired_app) ||
      !libhoth_ot_version_eq(staged_romext, desired_romext);

  if (staging_needs_update) {
    printf(
        "Only the staging slot needs updating. Performing DFU update x1...\n ");
    return 1;
  }

  printf("Device is already at the desired version. No DFU update needed.\n");
  return 0;
}

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

  bool force;
  if (htool_get_param_bool(inv, "force", &force)) {
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

  int update_cnt =
      force ? 2 : dfu_update_count(&desired_rom_ext, &desired_app, &resp);

  for (int i = 0; i < update_cnt; i++) {
    retval = libhoth_dfu_update(dev, image, statbuf.st_size, complete_flags);

    if (retval != 0) {
      fprintf(stderr, "DFU update failed\n");
      libhoth_print_dfu_error(dev, NULL);
      retval = -1;
      goto cleanup2;
    }

    retval = libhoth_opentitan_version(dev, &resp);
    if (retval != 0) {
      fprintf(stderr, "Failed to get ot version after dfu update\n");
      libhoth_print_dfu_error(dev, NULL);
      goto cleanup2;
    }

    if (!libhoth_ot_boot_slot_eq(&resp, &desired_rom_ext, &desired_app)) {
      fprintf(stderr, "Boot slot is wrong after dfu update %d\n", i);
      libhoth_print_dfu_error(dev, &resp);
      retval = -1;
      goto cleanup2;
    }
  }

  if (!libhoth_update_complete(&resp, &desired_rom_ext, &desired_app)) {
    fprintf(stderr, "DFU update failed\n");
    libhoth_print_dfu_error(dev, &resp);
    retval = -1;
    goto cleanup2;
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
