
#include "dfu_hostcmd.h"

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

#include "protocol/dfu_check.h"
#include "protocol/dfu_hostcmd.h"
#include "protocol/host_cmd.h"
#include "protocol/opentitan_version.h"
#include "protocol/status.h"

static int generate_random_nonce(struct hoth_dfu_session_id* session_id) {
  ssize_t ret = getrandom(&session_id->nonce, sizeof(session_id->nonce), 0);
  if (ret == -1) {
    perror("getrandom");
    return -1;
  }
  return 0;
}

libhoth_error libhoth_dfu_update(struct libhoth_device* dev,
                                 const uint8_t* image, size_t image_size,
                                 uint32_t complete_flags) {
  if (image == NULL) {
    return LIBHOTH_ERR_CONSTRUCT(HOTH_CTX_CMD_EXEC, HOTH_HOST_SPACE_LIBHOTH,
                                 LIBHOTH_ERR_INVALID_PARAMETER);
  }

  struct hoth_dfu_session_id session_id = {
      .target = HOTH_DFU_TARGET_EARLGREY_FW_UPDATE,
  };
  if (generate_random_nonce(&session_id) != 0) {
    fprintf(stderr, "Failed to generate random nonce.\n");
    return LIBHOTH_ERR_CONSTRUCT(HOTH_CTX_CMD_EXEC, HOTH_HOST_SPACE_LIBHOTH,
                                 LIBHOTH_ERR_FAIL);
  }

  struct {
    struct hoth_dfu_write_request_header hdr;
    uint8_t data[1000];
  } request = {.hdr = {.session_id = session_id}};
  static_assert(sizeof(request) == LIBHOTH_MAILBOX_SIZE - 8, "");

  size_t bytes_sent = 0;
  while (bytes_sent < image_size) {
    request.hdr.flags = bytes_sent == 0 ? HOTH_DFU_WRITE_FLAGS_NEW_SESSION : 0;

    size_t chunk_len = MIN(sizeof(request.data), image_size - bytes_sent);
    memcpy(request.data, &image[bytes_sent], chunk_len);

    size_t response_len;
    libhoth_error err = libhoth_hostcmd_exec_v2(
        dev, HOTH_CMD_DFU_WRITE, 0, &request, sizeof(request.hdr) + chunk_len,
        NULL, 0, &response_len);
    if (err != HOTH_SUCCESS) {
      fprintf(stderr, "DFU write failed with error code: 0x%016lx\n", err);
      return err;
    }
    if (response_len != 0) {
      fprintf(stderr, "DFU write expected 0 response bytes, got %zu\n",
              response_len);
      return LIBHOTH_ERR_CONSTRUCT(HOTH_CTX_CMD_EXEC, HOTH_HOST_SPACE_LIBHOTH,
                                   LIBHOTH_ERR_FAIL);
    }
    bytes_sent += chunk_len;
  }

  fprintf(stderr,
          "Completed sending fwupdate via DFU WRITE; sending DFU_COMPLETE to "
          "restart\n");

  struct hoth_dfu_complete_request complete_request = {
      .session_id = session_id,
      .flags = complete_flags,
  };
  size_t response_len = 0;
  libhoth_error err =
      libhoth_hostcmd_exec_v2(dev, HOTH_CMD_DFU_COMPLETE, 0, &complete_request,
                              sizeof(complete_request), NULL, 0, &response_len);
  if (err != HOTH_SUCCESS) {
    fprintf(stderr,
            "DFU complete failed with error code: 0x%016lx; ignoring as the "
            "chip may have already restarted.\n",
            err);
  }

  // TODO: Wait for chip to come back and confirm version
  usleep(LIBHOTH_REBOOT_DELAY_MS * 1000);
  int ret = libhoth_device_reconnect(dev);
  if (ret != LIBHOTH_OK) {
    return LIBHOTH_ERR_CONSTRUCT(HOTH_CTX_CMD_EXEC, HOTH_HOST_SPACE_LIBHOTH,
                                 ret);
  }
  return HOTH_SUCCESS;
}

static int dfu_update_count(
    const struct opentitan_image_version* desired_romext,
    const struct opentitan_image_version* desired_app,
    const struct opentitan_get_version_resp* resp) {
  uint32_t rom_ext_boot_slot = bootslot_int(resp->rom_ext.booted_slot);
  uint32_t rom_ext_stage_slot = rom_ext_boot_slot == 0 ? 1 : 0;
  uint32_t app_boot_slot = bootslot_int(resp->app.booted_slot);
  uint32_t app_stage_slot = app_boot_slot == 0 ? 1 : 0;

  const struct opentitan_image_version* booted_romext =
      &resp->rom_ext.slots[rom_ext_boot_slot];
  const struct opentitan_image_version* staged_romext =
      &resp->rom_ext.slots[rom_ext_stage_slot];
  const struct opentitan_image_version* booted_app =
      &resp->app.slots[app_boot_slot];
  const struct opentitan_image_version* staged_app =
      &resp->app.slots[app_stage_slot];

  bool booted_needs_update =
      (libhoth_ot_app_version_cmp_for_update(booted_app, desired_app) != 0) ||
      (libhoth_ot_rom_ext_version_cmp_for_update(booted_romext,
                                                 desired_romext) < 0);

  if (booted_needs_update) {
    printf(
        "The current bootslot is not the desired version. Performing DFU "
        "update x2...\n");
    return 2;
  }

  bool staging_needs_update =
      (libhoth_ot_app_version_cmp_for_update(staged_app, desired_app) != 0) ||
      (libhoth_ot_rom_ext_version_cmp_for_update(staged_romext,
                                                 desired_romext) < 0);

  if (staging_needs_update) {
    printf(
        "Only the staging slot needs updating. Performing DFU update x1...\n");
    return 1;
  }

  printf("Device is already at the desired version. No DFU update needed.\n");
  return 0;
}

libhoth_error libhoth_dfu_install_firmware(struct libhoth_device* dev,
                                           const uint8_t* image,
                                           size_t image_size,
                                           uint32_t complete_flags) {
  if (dev == NULL || image == NULL) {
    return LIBHOTH_ERR_CONSTRUCT(HOTH_CTX_CMD_EXEC, HOTH_HOST_SPACE_LIBHOTH,
                                 LIBHOTH_ERR_INVALID_PARAMETER);
  }

  struct opentitan_image_version desired_rom_ext = {0};
  struct opentitan_image_version desired_app = {0};
  struct opentitan_get_version_resp resp = {0};

  int retval = libhoth_extract_ot_bundle(image, image_size, &desired_rom_ext,
                                         &desired_app);
  if (retval != 0) {
    fprintf(stderr, "Failed to extract bundle (%d)\n", retval);
    return LIBHOTH_ERR_CONSTRUCT(HOTH_CTX_CMD_EXEC, HOTH_HOST_SPACE_LIBHOTH,
                                 retval);
  }

  retval = libhoth_opentitan_version(dev, &resp);
  if (retval != 0) {
    fprintf(stderr, "Failed to get current version (%d)\n", retval);
    return LIBHOTH_ERR_CONSTRUCT(HOTH_CTX_CMD_EXEC, HOTH_HOST_SPACE_LIBHOTH,
                                 retval);
  }

  if (desired_app.security_version < resp.bl0_min_sec_ver) {
    fprintf(
        stderr,
        "Desired application firmware security version %u is less than "
        "currently enforced minimum application firmware security version %u\n",
        desired_app.security_version, resp.bl0_min_sec_ver);
    return LIBHOTH_ERR_CONSTRUCT(HOTH_CTX_CMD_EXEC, HOTH_HOST_SPACE_LIBHOTH,
                                 LIBHOTH_ERR_INVALID_PARAMETER);
  }

  int update_cnt = dfu_update_count(&desired_rom_ext, &desired_app, &resp);

  for (int i = 0; i < update_cnt; i++) {
    libhoth_error err =
        libhoth_dfu_update(dev, image, image_size, complete_flags);
    if (err != HOTH_SUCCESS) {
      return err;
    }

    retval = libhoth_opentitan_version(dev, &resp);
    if (retval != 0) {
      fprintf(stderr, "Failed to get ot version after dfu update (%d)\n",
              retval);
      return LIBHOTH_ERR_CONSTRUCT(HOTH_CTX_CMD_EXEC, HOTH_HOST_SPACE_LIBHOTH,
                                   retval);
    }

    if (!libhoth_ot_check_update_successful(&resp, &desired_rom_ext,
                                            &desired_app)) {
      fprintf(stderr, "Boot slot is wrong after dfu update %d\n", i);
      return LIBHOTH_ERR_CONSTRUCT(HOTH_CTX_CMD_EXEC, HOTH_HOST_SPACE_LIBHOTH,
                                   LIBHOTH_ERR_FAIL);
    }
  }

  libhoth_error update_err =
      libhoth_update_complete(&resp, &desired_rom_ext, &desired_app);
  if (update_err != HOTH_SUCCESS) {
    fprintf(stderr,
            "DFU update failed, running image does not match expected after %d "
            "dfu updates\n",
            update_cnt);
    return update_err;
  }

  return HOTH_SUCCESS;
}
