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

#include "htool.h"

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

#include "../libhoth.h"
#include "ec_util.h"
#include "host_commands.h"
#include "htool_cmd.h"
#include "htool_console.h"
#include "htool_payload.h"
#include "htool_progress.h"
#include "htool_spi_proxy.h"
#include "htool_usb.h"

static int command_usb_list(const struct htool_invocation* inv) {
  return htool_usb_print_devices();
}

static int command_reboot(const struct htool_invocation* inv) {
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }
  struct ec_params_reboot_ec req = {
      .cmd = EC_REBOOT_COLD,
  };
  return htool_exec_hostcmd(dev, EC_CMD_REBOOT_EC, 0, &req, sizeof(req), NULL,
                            0, NULL);
}

static int command_get_version(const struct htool_invocation* inv) {
  struct libhoth_device* dev = htool_libhoth_device();
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
  struct libhoth_device* dev = htool_libhoth_device();
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

static int get_address_mode(const char* address_mode, bool* is_4_byte,
                            bool* enter_4byte) {
  if (!strcmp(address_mode, "3B/4B")) {
    *is_4_byte = true;
    *enter_4byte = true;
  } else if (!strcmp(address_mode, "3B")) {
    *is_4_byte = false;
    *enter_4byte = false;
  } else if (!strcmp(address_mode, "4B")) {
    *is_4_byte = true;
    *enter_4byte = false;
  } else {
    fprintf(stderr, "Invalid address_mode value: %s\n", address_mode);
    return -1;
  }
  return 0;
}

static int command_spi_read(const struct htool_invocation* inv) {
  struct {
    uint32_t start;
    uint32_t length;
    const char* dest_file;
    const char* address_mode;
  } args;
  if (htool_get_param_u32(inv, "start", &args.start) ||
      htool_get_param_u32(inv, "length", &args.length) ||
      htool_get_param_string(inv, "dest-file", &args.dest_file) ||
      htool_get_param_string(inv, "address_mode", &args.address_mode)) {
    return -1;
  }

  struct libhoth_device* dev = htool_libhoth_device();
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

  bool is_4_byte = true;
  bool enter_exit_4b = true;
  int status = get_address_mode(args.address_mode, &is_4_byte, &enter_exit_4b);
  if (status) {
    goto cleanup1;
  }
  struct htool_spi_proxy spi;
  status = htool_spi_proxy_init(&spi, dev, is_4_byte, enter_exit_4b);
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
    status = htool_spi_proxy_read(&spi, addr, buf, read_size);
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
    const char* address_mode;
  } args;
  if (htool_get_param_u32(inv, "start", &args.start) ||
      htool_get_param_bool(inv, "verify", &args.verify) ||
      htool_get_param_string(inv, "source-file", &args.source_file) ||
      htool_get_param_string(inv, "address_mode", &args.address_mode)) {
    return -1;
  }

  struct libhoth_device* dev = htool_libhoth_device();
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

  bool is_4_byte = true;
  bool enter_exit_4b = true;
  int status = get_address_mode(args.address_mode, &is_4_byte, &enter_exit_4b);
  if (status) {
    goto cleanup1;
  }
  struct htool_spi_proxy spi;
  status = htool_spi_proxy_init(&spi, dev, is_4_byte, enter_exit_4b);
  if (status) {
    goto cleanup2;
  }

  struct htool_progress_stderr progress;
  htool_progress_stderr_init(&progress, "Erasing/Programming");
  status = htool_spi_proxy_update(&spi, args.start, file_data, file_size,
                                  &progress.progress);
  if (status) {
    goto cleanup2;
  }

  if (args.verify) {
    struct htool_progress_stderr progress;
    htool_progress_stderr_init(&progress, "Verifying");
    status = htool_spi_proxy_verify(&spi, args.start, file_data, file_size,
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
  struct libhoth_device* dev = htool_libhoth_device();
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

  if (htool_get_param_bool(inv, "snapshot", &opts.snapshot)) {
    return -1;
  };

  if (!opts.snapshot) {
    if (htool_get_param_u32_or_fourcc(inv, "channel", &opts.channel_id) ||
        htool_get_param_bool(inv, "force_drive_tx", &opts.force_drive_tx) ||
        htool_get_param_bool(inv, "history", &opts.history) ||
        htool_get_param_bool(inv, "onlcr", &opts.onlcr) ||
        htool_get_param_u32(inv, "baud_rate", &opts.baud_rate)) {
      return -1;
    };
  }
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  if (opts.snapshot) {
    return htool_console_snapshot(dev);
  } else {
    return htool_console_run(dev, &opts);
  }
}

struct libhoth_device* htool_libhoth_device(void) {
  static struct libhoth_device* result;
  if (result) {
    return result;
  }

  int rv;
  const char* transport_method_str;
  rv = htool_get_param_string(htool_global_flags(), "transport",
                              &transport_method_str);
  if (rv) {
    return NULL;
  }

  if (strlen(transport_method_str) <= 0 ||
      (strcmp(transport_method_str, "usb") == 0)) {
    result = htool_libhoth_usb_device();
  } else if (strcmp(transport_method_str, "spidev") == 0) {
    result = htool_libhoth_spi_device();
  } else if (strcmp(transport_method_str, "mtd") == 0) {
    result = htool_libhoth_mtd_device();
  } else {
    fprintf(stderr, "Unknown transport protocol %s\n\r\n",
            transport_method_str);
    return NULL;
  }

  return result;
}

int htool_exec_hostcmd(struct libhoth_device* dev, uint16_t command,
                       uint8_t version, const void* req_payload,
                       size_t req_payload_size, void* resp_buf,
                       size_t resp_buf_size, size_t* out_resp_size) {
  struct {
    struct ec_host_request hdr;
    uint8_t payload_buf[LIBHOTH_MAILBOX_SIZE - sizeof(struct ec_host_request)];
  } req;
  if (req_payload_size > sizeof(req.payload_buf)) {
    fprintf(stderr, "req_payload_size too large: %d > %d\n",
            (int)req_payload_size, (int)sizeof(req.payload_buf));
    return -1;
  }
  if (req_payload) {
    memcpy(req.payload_buf, req_payload, req_payload_size);
  }
  int status = populate_ec_request_header(command, version, req.payload_buf,
                                          req_payload_size, &req.hdr);
  if (status != 0) {
    fprintf(stderr, "populate_request_header failed: %d\n", status);
    return -1;
  }
  status = libhoth_send_request(dev, &req, sizeof(req.hdr) + req_payload_size);
  if (status != LIBHOTH_OK) {
    fprintf(stderr, "libhoth_usb_send() failed: %d\n", status);
    return -1;
  }
  struct {
    struct ec_host_response hdr;
    uint8_t payload_buf[LIBHOTH_MAILBOX_SIZE - sizeof(struct ec_host_response)];
  } resp;
  size_t resp_size;
  status = libhoth_receive_response(dev, &resp, sizeof(resp), &resp_size,
                                    /*timeout_ms=*/5000);
  if (status != LIBHOTH_OK) {
    fprintf(stderr, "libhoth_usb_receive_response() failed: %d\n", status);
    return -1;
  }
  status = validate_ec_response_header(&resp.hdr, resp.payload_buf, resp_size);
  if (status != 0) {
    fprintf(stderr, "EC response header invalid: %d\n", status);
    return -1;
  }
  if (resp.hdr.result != EC_RES_SUCCESS) {
    fprintf(stderr, "EC response contained error: %d\n", resp.hdr.result);
    return HTOOL_ERROR_HOST_COMMAND_START + resp.hdr.result;
  }

  size_t resp_payload_size = resp_size - sizeof(struct ec_host_response);
  if (out_resp_size) {
    if (resp_payload_size > resp_buf_size) {
      fprintf(
          stderr,
          "Response payload too large to fit in supplied buffer: %zu > %zu\n",
          resp_payload_size, resp_buf_size);
      return -1;
    }
  } else {
    if (resp_payload_size != resp_buf_size) {
      fprintf(stderr,
              "Unexpected response payload size: got %zu expected %zu\n",
              resp_payload_size, resp_buf_size);
      return -1;
    }
  }
  if (resp_buf) {
    memcpy(resp_buf, resp.payload_buf, resp_payload_size);
  }
  if (out_resp_size) {
    *out_resp_size = resp_payload_size;
  }
  return 0;
}

static const struct htool_cmd CMDS[] = {
    {
        .verbs = (const char*[]){"usb", "list", NULL},
        .desc = "List all RoTs connected via USB.",
        .params = (const struct htool_param[]){{}},
        .func = command_usb_list,
    },
    {
        .verbs = (const char*[]){"reboot", NULL},
        .alias = (const char*[]){"ec_reboot", NULL},
        .desc = "Reboot the RoT.",
        .params = (const struct htool_param[]){{}},
        .func = command_reboot,
    },
    {
        .verbs = (const char*[]){"show", "firmware_version", NULL},
        .alias = (const char*[]){"ec_get_version", NULL},
        .desc = "Get the version of the RoT firmware.",
        .params = (const struct htool_param[]){{}},
        .func = command_get_version,
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
                {HTOOL_FLAG_VALUE, 'a', "address_mode", "3B/4B",
                 .desc =
                     "3B: 3 byte mode no enter/exit 4B supported\n"
                     "\t3B/4B: 3 Byte current but enter 4B for SPI operation\n"
                     "\t4B: 4 byte mode only, no enter/exit 4B supported"},
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
                {HTOOL_FLAG_VALUE, 'a', "address_mode", "3B/4B",
                 .desc =
                     "3B: 3 byte mode no enter/exit 4B supported\n"
                     "\t3B/4B: 3 Byte current but enter 4B for SPI operation\n"
                     "\t4B: 4 byte mode only, no enter/exit 4B supported"},
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
                {HTOOL_FLAG_BOOL, 'n', "onlcr", "false",
                 .desc = "Translate received \"\\n\" to \"\\r\\n\"."},
                {HTOOL_FLAG_VALUE, 'b', "baud_rate", "0"},
                {HTOOL_FLAG_BOOL, 's', "snapshot", "false",
                 .desc = "Print a snapshot of most recent console messages."},
                {}},
        .func = command_console,
    },
    {
        .verbs = (const char*[]){"payload", "status", NULL},
        .desc = "Show payload status",
        .params = (const struct htool_param[]){{}},
        .func = htool_payload_status,
    },
    {},
};

static const struct htool_param GLOBAL_FLAGS[] = {
    {HTOOL_FLAG_VALUE, .name = "transport", .default_value = "",
     .desc = "The method of connecting to the RoT; for example "
             "'spidev'/'usb'/'mtd'"},
    {HTOOL_FLAG_VALUE, .name = "usb_loc", .default_value = "",
     .desc = "The full bus-portlist location of the RoT; for example "
             "'1-10.4.4.1'."},
    {HTOOL_FLAG_VALUE, .name = "usb_product", .default_value = "",
     .desc = "If there is a single USB RoT with this substring in the USB "
             "product string, use it."},
    {HTOOL_FLAG_VALUE, .name = "spidev_path", .default_value = "",
     .desc = "The full SPIDEV path of the RoT; for example "
             "'/dev/spidev0.0'."},
    {HTOOL_FLAG_VALUE, .name = "mtddev_path", .default_value = "",
     .desc = "The full MTD path of the RoT mailbox; for example "
             "'/dev/mtd0'. If unspecified, will attempt to detect "
             "the correct device automatically"},
    {HTOOL_FLAG_VALUE, .name = "mtddev_name", .default_value = "hoth-mailbox",
     .desc = "The MTD name of the RoT mailbox; for example 'hoth-mailbox'. "},
    {HTOOL_FLAG_VALUE, .name = "mailbox_location", .default_value = "0",
     .desc = "The location of the mailbox on the RoT, for 'spidev' "
             "or 'mtd' transports; for example '0x900000'."},
    {}};

int main(int argc, const char* const* argv) {
  return htool_main(GLOBAL_FLAGS, CMDS, argc - 1, &argv[1]);
}
