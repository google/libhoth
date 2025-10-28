
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
#include "protocol/dfu_hostcmd.h"

int htool_dfu_update(const struct htool_invocation* inv) {
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

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

  if (libhoth_dfu_update(dev, image, statbuf.st_size, complete_flags) != 0) {
    fprintf(stderr, "DFU update failed.\n");
    goto cleanup2;
  }
  retval = 0;

cleanup2:
  int ret = munmap(image, statbuf.st_size);
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