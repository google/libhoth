
#include "dfu_check.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
// for MIN()
#include <sys/param.h>
#include <sys/random.h>
#include <time.h>
#include <unistd.h>

#include "protocol/host_cmd.h"
#include "protocol/opentitan_version.h"

int libhoth_dfu_check(const uint8_t* image, size_t image_size, struct opentitan_get_version_resp * resp) {

  int retval = 0;
  struct opentitan_image_version desired_rom_ext = {0};
  struct opentitan_image_version desired_app = {0};

  // Populate rom_ext and app with the desired extracted versions from the image
  retval = libhoth_extract_ot_bundle(image, &desired_rom_ext, &desired_app);

  if(retval != 0) {
    fprintf(stderr, "Failed to extract bundle\n");
  }

  // Determine the stage slot for each ot get version to compare
  uint32_t rom_ext_boot_slot = bootslot_int(resp->rom_ext.booted_slot);
  uint32_t rom_ext_stage_slot = rom_ext_boot_slot == 0 ? 1 : 0;
  uint32_t app_boot_slot = bootslot_int(resp->app.booted_slot);
  uint32_t app_stage_slot = app_boot_slot == 0 ? 1 : 0;

  bool booted_slot_eq = libhoth_ot_version_eq(&resp->rom_ext.slots[rom_ext_boot_slot], &desired_rom_ext) && libhoth_ot_version_eq(&resp->app.slots[app_boot_slot], &desired_app);
  if(!booted_slot_eq) {
    // TODO print failure message
    printf("Booted slot does not match desired version.\n");
    return -1;
  }

  bool staging_slot_eq = libhoth_ot_version_eq(&resp->rom_ext.slots[rom_ext_stage_slot], &desired_rom_ext) && libhoth_ot_version_eq(&resp->app.slots[app_stage_slot], &desired_app);
  if(!staging_slot_eq) {
    // TODO print failure message
    printf("Staging slot does not match desired version.\n");
    return -1;
  }

  return 0;
  
}
