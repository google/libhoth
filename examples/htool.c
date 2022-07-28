// Copyright 2022 Google LLC
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

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "../libhoth_usb.h"
#include "ec_util.h"
#include "host_commands.h"
#include "htool_cmd.h"
#include "htool_console.h"
#include "htool_progress.h"
#include "htool_spi.h"
#include "htool_usb.h"

static int command_usb_list(const struct htool_invocation* inv) {
  return htool_usb_print_devices();
}

static int command_ec_reboot(const struct htool_invocation* inv) {
  struct libhoth_usb_device* dev = htool_libhoth_usb_device();
  if (!dev) {
    return -1;
  }
  struct ec_params_reboot_ec req = {
      .cmd = EC_REBOOT_COLD,
  };
  return htool_exec_hostcmd(dev, EC_CMD_REBOOT_EC, 0, &req, sizeof(req), NULL,
                            0, NULL);
}

static int command_ec_get_version(const struct htool_invocation* inv) {
  struct libhoth_usb_device* dev = htool_libhoth_usb_device();
  if (!dev) {
    return -1;
  }
  struct ec_response_get_version response;
  int status = htool_exec_hostcmd(dev, EC_CMD_GET_VERSION, /*version=*/0, NULL,
                                  0, &response, sizeof(response), NULL);
  if (status) {
    return -1;
  }
  printf("version_string_ro: %.*s\n", (int)sizeof(response.version_string_ro),
         response.version_string_ro);
  printf("version_string_rw: %.*s\n", (int)sizeof(response.version_string_rw),
         response.version_string_rw);
  return 0;
}

static int command_show_chipinfo(const struct htool_invocation* inv) {
  struct libhoth_usb_device* dev = htool_libhoth_usb_device();
  if (!dev) {
    return -1;
  }
  struct ec_response_chip_info response;
  int status = htool_exec_hostcmd(
      dev, EC_CMD_BOARD_SPECIFIC_BASE + EC_PRV_CMD_HOTH_CHIP_INFO,
      /*version=*/0, NULL, 0, &response, sizeof(response), NULL);
  if (status != 0) {
    return -1;
  }
  printf("Chip Info:\n");
  printf("Hardware Identity: 0x%016llx\n",
         (unsigned long long)response.hardware_identity);
  printf("Hardware Category: %d\n", response.hardware_category);
  printf("Info Variant: %lu\n", (unsigned long)response.info_variant);
  return 0;
}

static int force_write(int fd, const void* buf, size_t size) {
  const uint8_t* cbuf = (const uint8_t*)buf;
  while (size > 0) {
    ssize_t bytes_written = write(fd, cbuf, size);
    if (bytes_written <= 0) {
      perror("write failed");
      return -1;
    }
    size -= bytes_written;
    cbuf += bytes_written;
  }
  return 0;
}

static int command_spi_read(const struct htool_invocation* inv) {
  struct {
    uint32_t start;
    uint32_t length;
    const char* dest_file;
  } args;
  if (htool_get_param_u32(inv, "start", &args.start) ||
      htool_get_param_u32(inv, "length", &args.length) ||
      htool_get_param_string(inv, "dest-file", &args.dest_file)) {
    return -1;
  }

  struct libhoth_usb_device* dev = htool_libhoth_usb_device();
  if (!dev) {
    return -1;
  }

  int result = -1;

  int fd = open(args.dest_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd == -1) {
    fprintf(stderr, "Error opening file %s: %s\n", args.dest_file,
            strerror(errno));
    return -1;
  }

  struct htool_spi spi;
  int status = htool_spi_init(&spi, dev);
  if (status) {
    goto cleanup1;
  }

  struct htool_progress_stderr progress;
  htool_progress_stderr_init(&progress, "Reading");

  uint32_t addr = args.start;
  size_t len_remaining = args.length;
  while (len_remaining > 0) {
    uint8_t buf[65536];
    size_t read_size = MIN(len_remaining, sizeof(buf));
    status = htool_spi_read(&spi, addr, buf, read_size);
    if (status) {
      goto cleanup1;
    }
    status = force_write(fd, buf, read_size);
    if (status) {
      goto cleanup1;
    }

    addr += read_size;
    len_remaining -= read_size;

    progress.progress.func(progress.progress.param, args.length - len_remaining,
                           args.length);
  }

  result = 0;

cleanup1:
  close(fd);
  return result;
}

static int command_spi_update(const struct htool_invocation* inv) {
  struct {
    uint32_t start;
    bool verify;
    const char* source_file;
  } args;
  if (htool_get_param_u32(inv, "start", &args.start) ||
      htool_get_param_bool(inv, "verify", &args.verify) ||
      htool_get_param_string(inv, "source-file", &args.source_file)) {
    return -1;
  }

  struct libhoth_usb_device* dev = htool_libhoth_usb_device();
  if (!dev) {
    return -1;
  }

  int result = -1;

  int fd = open(args.source_file, O_RDONLY, 0);
  if (fd == -1) {
    fprintf(stderr, "Error opening file %s: %s\n", args.source_file,
            strerror(errno));
    return -1;
  }
  struct stat statbuf;
  if (fstat(fd, &statbuf)) {
    fprintf(stderr, "fstat error: %s\n", strerror(errno));
    goto cleanup1;
  }
  if (statbuf.st_size > SIZE_MAX) {
    fprintf(stderr, "file to large\n");
    goto cleanup1;
  }
  size_t file_size = statbuf.st_size;
  uint8_t* file_data = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);

  struct htool_spi spi;
  int status = htool_spi_init(&spi, dev);
  if (status) {
    goto cleanup2;
  }

  struct htool_progress_stderr progress;
  htool_progress_stderr_init(&progress, "Erasing/Programming");
  status = htool_spi_update(&spi, args.start, file_data, file_size,
                            &progress.progress);
  if (status) {
    goto cleanup2;
  }

  if (args.verify) {
    struct htool_progress_stderr progress;
    htool_progress_stderr_init(&progress, "Verifying");
    status = htool_spi_verify(&spi, args.start, file_data, file_size,
                              &progress.progress);
    if (status) {
      goto cleanup2;
    }
  }

  result = 0;

cleanup2:
  munmap(file_data, file_size);

cleanup1:
  close(fd);
  return result;
}

static int do_target_reset(uint32_t reset_option) {
  struct libhoth_usb_device* dev = htool_libhoth_usb_device();
  if (!dev) {
    return -1;
  }
  struct ec_request_reset_target req = {
      .target_id = RESET_TARGET_ID_RSTCTRL0,
      .reset_option = reset_option,
  };
  return htool_exec_hostcmd(
      dev, EC_CMD_BOARD_SPECIFIC_BASE + EC_PRV_CMD_HOTH_RESET_TARGET, 0, &req,
      sizeof(req), NULL, 0, NULL);
}

static int command_target_reset_on(const struct htool_invocation* inv) {
  return do_target_reset(EC_TARGET_RESET_OPTION_SET);
}

static int command_target_reset_off(const struct htool_invocation* inv) {
  return do_target_reset(EC_TARGET_RESET_OPTION_RELEASE);
}

static int command_target_reset_pulse(const struct htool_invocation* inv) {
  return do_target_reset(EC_TARGET_RESET_OPTION_PULSE);
}

static int command_console(const struct htool_invocation* inv) {
  struct htool_console_opts opts = {};

  if (htool_get_param_u32_or_fourcc(inv, "channel", &opts.channel_id) ||
      htool_get_param_bool(inv, "force_drive_tx", &opts.force_drive_tx) ||
      htool_get_param_bool(inv, "history", &opts.history) ||
      htool_get_param_bool(inv, "onlcr", &opts.onlcr)) {
    return -1;
  };
  struct libhoth_usb_device* dev = htool_libhoth_usb_device();
  if (!dev) {
    return -1;
  }
  return htool_console_run(dev, &opts);
}

static const struct htool_cmd CMDS[] = {
    {
        .verbs = (const char*[]){"usb", "list", NULL},
        .desc = "List all RoTs connected via USB.",
        .params = (const struct htool_param[]){{}},
        .func = command_usb_list,
    },
    {
        .verbs = (const char*[]){"ec_reboot", NULL},
        .desc = "Reboot the RoT.",
        .params = (const struct htool_param[]){{}},
        .func = command_ec_reboot,
    },
    {
        .verbs = (const char*[]){"ec_get_version", NULL},
        .desc = "Get the version of the RoT firmware.",
        .params = (const struct htool_param[]){{}},
        .func = command_ec_get_version,
    },
    {
        .verbs = (const char*[]){"show", "chipinfo", NULL},
        .desc = "Return details about this specific RoT chip.",
        .params = (const struct htool_param[]){{}},
        .func = command_show_chipinfo,
    },
    {
        .verbs = (const char*[]){"spi", "read", NULL},
        .desc = "Read from SPI flash into a file",
        .params =
            (const struct htool_param[]){
                {HTOOL_FLAG_VALUE, 's', "start", "0", .desc = "start address"},
                {HTOOL_FLAG_VALUE, 'n', "length",
                 .desc = "the number of bytes to read"},
                {HTOOL_POSITIONAL, .name = "dest-file"},
                {}},
        .func = command_spi_read,
    },
    {
        .verbs = (const char*[]){"spi", "update", NULL},
        .desc = "Write a file to SPI flash (erase + program).",
        .params =
            (const struct htool_param[]){
                {HTOOL_FLAG_VALUE, 's', "start", "0", .desc = "start address"},
                {HTOOL_FLAG_BOOL, 'v', "verify", "true"},
                {HTOOL_POSITIONAL, .name = "source-file"},
                {}},
        .func = command_spi_update,
    },
    {
        .verbs = (const char*[]){"target", "reset", "on", NULL},
        .desc = "Put the target device into reset.",
        .params = (const struct htool_param[]){{}},
        .func = command_target_reset_on,
    },
    {
        .verbs = (const char*[]){"target", "reset", "off", NULL},
        .desc = "Take the target device out of reset",
        .params = (const struct htool_param[]){{}},
        .func = command_target_reset_off,
    },
    {
        .verbs = (const char*[]){"target", "reset", "pulse", NULL},
        .desc = "Quickly put the target device in and out of reset",
        .params = (const struct htool_param[]){{}},
        .func = command_target_reset_pulse,
    },
    {
        .verbs = (const char*[]){"console", NULL},
        .desc = "Open a console for communicating with the RoT or devices "
                "attached to the RoT.",
        .params =
            (const struct htool_param[]){
                {HTOOL_FLAG_VALUE, 'c', "channel", NULL,
                 .desc = "Which channel to talk to. Typically a fourcc code."},
                {HTOOL_FLAG_BOOL, 'f', "force_drive_tx", "0",
                 .desc = "Drive the UART's TX net even if the RoT isn't sure "
                         "whether some other device else is driving it. Only "
                         "use this option if you are CERTAIN there is no "
                         "debugging hardware attached."},
                {HTOOL_FLAG_BOOL, 'h', "history", "false",
                 .desc = "Include data bufferred before the current time."},
                {HTOOL_FLAG_BOOL, 'l', "onlcr", "false",
                 .desc = "Translate received \"\\n\" to \"\\r\\n\"."},
                {}},
        .func = command_console,
    },

    {},
};

static const struct htool_param GLOBAL_FLAGS[] = {
    {HTOOL_FLAG_VALUE, .name = "usb_loc", .default_value = "",
     .desc = "The full bus-portlist location of the RoT; for example "
             "'1-10.4.4.1'."},
    {HTOOL_FLAG_VALUE, .name = "usb_product", .default_value = "",
     .desc = "If there is a single USB RoT with this substring in the USB "
             "product string, use it."},
    {}};

int main(int argc, const char* const* argv) {
  return htool_main(GLOBAL_FLAGS, CMDS, argc - 1, &argv[1]);
}
