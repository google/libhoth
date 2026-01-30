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

#include "dfu_check.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// for MIN()
#include <sys/param.h>
#include <sys/random.h>
#include <time.h>
#include <unistd.h>

#include "protocol/console.h"
#include "protocol/host_cmd.h"
#include "protocol/opentitan_version.h"

void libhoth_print_boot_log(struct opentitan_image_version* booted_rom_ext,
                            struct opentitan_image_version* booted_app,
                            struct opentitan_image_version* desired_rom_ext,
                            struct opentitan_image_version* desired_app) {
  printf("installed_version: \"%d.%d\"\n", desired_app->major,
         desired_app->minor);
  printf("activated_versions: {\n");
  printf("key: \"app\"\n");
  printf("value: \"%d.%d\"\n", booted_app->major, booted_app->minor);
  printf("}\n");

  printf("activated_versions: {\n");
  printf("key: \"rom_ext\"\n");
  printf("value: \"%d.%d\"\n", booted_rom_ext->major, booted_rom_ext->minor);
  printf("}\n");
}

void libhoth_print_dfu_error(struct libhoth_device* const dev,
                             struct opentitan_get_version_resp* resp) {
  fprintf(
      stderr,
      "Error: Mismatch detected between the current and desired versions.\n");

  printf("tool_failure_code: -1\n");
  printf("notes: \"");
  libhoth_print_ot_version_resp(resp);
  libhoth_print_erot_console(dev);
  // Added to enclosed the "" within the notes field
  printf("\"\n");
}

int libhoth_dfu_check(struct libhoth_device* const dev, const uint8_t* image,
                      size_t image_size,
                      struct opentitan_get_version_resp* resp) {
  int retval = 0;
  struct opentitan_image_version desired_rom_ext = {0};
  struct opentitan_image_version desired_app = {0};

  // Populate rom_ext and app with the desired extracted versions from the image
  retval = libhoth_extract_ot_bundle(image, image_size, &desired_rom_ext,
                                     &desired_app);

  if (retval != 0) {
    fprintf(stderr, "Error: Failed to extract bundle with code %d\n", retval);
  }

  // Determine the stage slot for each ot get version to compare
  uint32_t rom_ext_boot_slot = bootslot_int(resp->rom_ext.booted_slot);
  uint32_t rom_ext_stage_slot = rom_ext_boot_slot == 0 ? 1 : 0;
  uint32_t app_boot_slot = bootslot_int(resp->app.booted_slot);
  uint32_t app_stage_slot = app_boot_slot == 0 ? 1 : 0;

  // Always print out on non-error OR error the installed and active version for
  // parsing purpose
  libhoth_print_boot_log(&resp->rom_ext.slots[rom_ext_boot_slot],
                         &resp->app.slots[app_boot_slot], &desired_rom_ext,
                         &desired_app);

  bool booted_slot_eq =
      libhoth_ot_version_eq(&resp->rom_ext.slots[rom_ext_boot_slot],
                            &desired_rom_ext) &&
      libhoth_ot_version_eq(&resp->app.slots[app_boot_slot], &desired_app);
  if (!booted_slot_eq) {
    libhoth_print_dfu_error(dev, resp);
    return -1;
  }

  bool staging_slot_eq =
      libhoth_ot_version_eq(&resp->rom_ext.slots[rom_ext_stage_slot],
                            &desired_rom_ext) &&
      libhoth_ot_version_eq(&resp->app.slots[app_stage_slot], &desired_app);
  if (!staging_slot_eq) {
    libhoth_print_dfu_error(dev, resp);
    return -1;
  }

  return 0;
}
