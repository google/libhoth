
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

#include "protocol/host_cmd.h"

static int generate_random_nonce(struct hoth_dfu_session_id* session_id) {
  ssize_t ret = getrandom(&session_id->nonce, sizeof(session_id->nonce), 0);
  if (ret == -1) {
    perror("getrandom");
    return -1;
  }
  return 0;
}

int libhoth_dfu_update(struct libhoth_device* dev, const uint8_t* image,
                       size_t image_size, uint32_t complete_flags) {
  struct hoth_dfu_session_id session_id = {
      .target = HOTH_DFU_TARGET_EARLGREY_FW_UPDATE,
  };
  if (generate_random_nonce(&session_id) != 0) {
    fprintf(stderr, "Failed to generate random nonce.\n");
    return -1;
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
    int ret = libhoth_hostcmd_exec(dev, HOTH_CMD_DFU_WRITE, 0, &request,
                                   sizeof(request.hdr) + chunk_len, NULL, 0,
                                   &response_len);
    if (ret != 0) {
      fprintf(stderr, "DFU write failed with error code: %d\n", ret);
      return -1;
    }
    if (response_len != 0) {
      fprintf(stderr, "DFU write expected 0 response bytes, got %zu\n",
              response_len);
      return -1;
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
  int ret =
      libhoth_hostcmd_exec(dev, HOTH_CMD_DFU_COMPLETE, 0, &complete_request,
                           sizeof(complete_request), NULL, 0, &response_len);
  if (ret != 0) {
    fprintf(stderr,
            "DFU complete failed with error code: %d; ignoring as the "
            "chip may have already restarted.\n",
            ret);
  }

  // TODO: Wait for chip to come back and confirm version
  return libhoth_device_reconnect(dev);
}
