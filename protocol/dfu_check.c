
#include "dfu_check.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// for MIN()
#include <sys/param.h>
#include <sys/random.h>
#include <time.h>
#include <unistd.h>

#include "protocol/host_cmd.h"
#include "protocol/opentitan_version.h"

int libhoth_dfu_check(struct libhoth_device* dev, const uint8_t* image,
                       size_t image_size, struct opentitan_get_version_resp resp) {

  int retval = 0;
  struct opentitan_image_version desired_rom_ext = {0};
  struct opentitan_image_version desired_app = {0};

  // Populate rom_ext and app with the desired extracted versions from the image
  retval = libhoth_extract_ot_bundle(image, &desired_rom_ext, &desired_app);

  if(retval != 0) {
    fprintf(stderr, "Failed to extract bundle\n");
  }

  // Determine the stage slot for each ot get version to compare
  uint32_t rom_ext_boot_slot = bootslot_int(resp.rom_ext.booted_slot);
  uint32_t rom_ext_stage_slot = rom_ext_boot_slot == 0 ? 1 : 0;
  uint32_t app_boot_slot = bootslot_int(resp.app.booted_slot);
  uint32_t app_stage_slot = app_boot_slot == 0 ? 1 : 0;

  // Compare the desired version with the current bootslot version
  // If they are different, we need to automatically perform the x2 update
  // If both are the same & the staged slot is different, we need to perform a single update
  // For all other cases, no update is needed
  if(libhoth_ot_version_eq(&resp.rom_ext.slots[rom_ext_boot_slot], &desired_rom_ext) == 0 ||
     libhoth_ot_version_eq(&resp.app.slots[app_boot_slot], &desired_app) == 0 ) {
          printf("The current bootslot is not the desired version.\n");

        }
    else{
      if(libhoth_ot_version_eq(&resp.rom_ext.slots[rom_ext_stage_slot], &desired_rom_ext) == 0 ||
         libhoth_ot_version_eq(&resp.app.slots[app_stage_slot], &desired_app) == 0 ) {
              printf("The staged slot is not the desired version.\n");
        }
        else{
          printf("Device is already at the desired version.\n");
        }
    }
  
}
