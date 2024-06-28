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
#include "authorization_record.h"
#include "ec_util.h"
#include "host_commands.h"
#include "htool_cmd.h"
#include "htool_console.h"
#include "htool_i2c.h"
#include "htool_jtag.h"
#include "htool_panic.h"
#include "htool_payload.h"
#include "htool_payload_update.h"
#include "htool_progress.h"
#include "htool_raw_host_command.h"
#include "htool_spi_proxy.h"
#include "htool_srtm.h"
#include "htool_statistics.h"
#include "htool_target_usb.h"
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

static int command_authz_record_read(const struct htool_invocation* inv) {
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }
  struct ec_authz_record_get_request request = {.index = 0};
  struct ec_authz_record_get_response response = {};
  int status = htool_exec_hostcmd(
      dev, EC_CMD_BOARD_SPECIFIC_BASE + EC_PRV_CMD_HOTH_GET_AUTHZ_RECORD,
      /*version=*/0, &request, sizeof(request), &response, sizeof(response),
      NULL);
  if (status != 0) {
    return -1;
  }
  printf("Index: %d \n", response.index);
  printf("Valid: %d \n", response.valid);
  printf("Record:\n");
  authorization_record_print_hex_string(&response.record);
  return 0;
}

static int command_authz_record_erase(const struct htool_invocation* inv) {
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }
  struct ec_authz_record_set_request request = {
      .index = 0,
      .erase = 1,
  };
  int status = htool_exec_hostcmd(
      dev, EC_CMD_BOARD_SPECIFIC_BASE + EC_PRV_CMD_HOTH_SET_AUTHZ_RECORD,
      /*version=*/0, &request, sizeof(request), NULL, 0, NULL);
  if (status != 0) {
    return -1;
  }
  return 0;
}

static int command_authz_record_build(const struct htool_invocation* inv) {
  uint32_t caps;
  if (htool_get_param_u32(inv, "caps", &caps)) {
    return -1;
  }

  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  int status;
  struct authorization_record record = {
      .magic = AUTHORIZATION_RECORD_MAGIC,
      .version = 1,
      .size = AUTHORIZATION_RECORD_SIZE,
      .flags = 0,
  };
  *(uint32_t*)record.capabilities = caps;

  struct ec_response_chip_info chipinfo_resp;
  status = htool_exec_hostcmd(
      dev, EC_CMD_BOARD_SPECIFIC_BASE + EC_PRV_CMD_HOTH_CHIP_INFO,
      /*version=*/0, NULL, 0, &chipinfo_resp, sizeof(chipinfo_resp), NULL);
  if (status != 0) {
    return -1;
  }
  record.dev_id_0 = chipinfo_resp.hardware_identity & 0xfffffffful;
  record.dev_id_1 = (chipinfo_resp.hardware_identity >> 32);

  struct ec_authz_record_get_nonce_response nonce_resp;
  status = htool_exec_hostcmd(
      dev, EC_CMD_BOARD_SPECIFIC_BASE + EC_PRV_CMD_HOTH_GET_AUTHZ_RECORD_NONCE,
      /*version=*/0, NULL, 0, &nonce_resp, sizeof(nonce_resp), NULL);
  if (status != 0) {
    return -1;
  }
  if (nonce_resp.ro_supported_key_id == 0) {
    fprintf(stderr,
            "ro_supported_key_id = 0. Please reset the chip and retry\n");
    return -1;
  }
  if (nonce_resp.ro_supported_key_id != nonce_resp.rw_supported_key_id) {
    fprintf(
        stderr,
        "RO and RW supported key_ids do not match: (RO) 0x%x != (RW) 0x%x\n",
        nonce_resp.ro_supported_key_id, nonce_resp.rw_supported_key_id);
    return -1;
  }
  record.key_id = nonce_resp.ro_supported_key_id;
  if (sizeof(record.authorization_nonce) !=
      sizeof(nonce_resp.authorization_nonce)) {
    fprintf(stderr, "Nonce size does not match. Expecting %ld, got %ld",
            sizeof(nonce_resp.authorization_nonce),
            sizeof(record.authorization_nonce));
    return -1;
  }
  memcpy(record.authorization_nonce, nonce_resp.authorization_nonce,
         sizeof(record.authorization_nonce));

  printf("Record:\n");
  authorization_record_print_hex_string(&record);
  return 0;
}

static int command_authz_record_set(const struct htool_invocation* inv) {
  const char* record_hex;
  if (htool_get_param_string(inv, "record", &record_hex)) {
    return -1;
  }

  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  struct ec_authz_record_set_request request = {
      .index = 0,
      .erase = 0,
  };
  int status = authorization_record_from_hex_string(&request.record, record_hex,
                                                    strlen(record_hex));
  if (status != 0) {
    fprintf(stderr, "Error reading authorization record from hex string\n");
    return -1;
  }
  status = htool_exec_hostcmd(
      dev, EC_CMD_BOARD_SPECIFIC_BASE + EC_PRV_CMD_HOTH_SET_AUTHZ_RECORD,
      /*version=*/0, &request, sizeof(request), NULL, 0, NULL);
  if (status != 0) {
    return -1;
  }
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
    fprintf(stderr, "file too large\n");
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
  }
  if (!opts.snapshot) {
    if (htool_get_param_u32_or_fourcc(inv, "channel", &opts.channel_id) ||
        htool_get_param_bool(inv, "force_drive_tx", &opts.force_drive_tx) ||
        htool_get_param_bool(inv, "history", &opts.history) ||
        htool_get_param_bool(inv, "onlcr", &opts.onlcr) ||
        htool_get_param_u32(inv, "baud_rate", &opts.baud_rate) ||
        htool_get_param_u32(inv, "claim_timeout_secs",
                            &opts.claim_timeout_secs) ||
        htool_get_param_u32(inv, "yield_ms", &opts.yield_ms)) {
      return -1;
    }
  } else {
    if (htool_has_param(inv, "channel")) {
      if (htool_get_param_u32_or_fourcc(inv, "channel", &opts.channel_id)) {
        return -1;
      }
    } else {
      // Channel is optional in snapshot mode: 0 = legacy host command.
      opts.channel_id = 0;
    }
  }
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  if (opts.snapshot) {
    return htool_console_snapshot(dev, &opts);
  } else {
    return htool_console_run(dev, &opts);
  }
}

static int command_flash_spi_info(const struct htool_invocation* inv) {
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }
  struct ec_response_flash_spi_info response;
  int status = htool_exec_hostcmd(dev, EC_CMD_FLASH_SPI_INFO, /*version=*/0,
                                  NULL, 0, &response, sizeof(response), NULL);
  if (status) {
    return -1;
  }
  uint32_t jedec_id =
      (response.jedec[2] << 16) | (response.jedec[1] << 8) | response.jedec[0];
  uint32_t device_id = (response.mfr_dev_id[1] << 8) | response.mfr_dev_id[0];
  if ((jedec_id == 0) && (device_id == 0)) {
    fprintf(
        stderr,
        "This is likely because the target device is not in reset, and thus it "
        "is not safe to use the SPI bus through a non-SPI transport. Try using "
        "'htool target reset on' to put the target in reset first.\n");
    return -1;
  }
  printf("Jedec ID: 0x%x\n", jedec_id);
  printf("Device ID: 0x%x\n", device_id);
  printf("Status Reg1: 0x%x\n", response.sr1);
  printf("Status Reg2: 0x%x\n", response.sr2);
  return 0;
}

static int command_arm_coordinated_reset(const struct htool_invocation* inv) {
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  return htool_exec_hostcmd(
      dev, EC_CMD_BOARD_SPECIFIC_BASE + EC_PRV_CMD_HOTH_ARM_COORDINATED_RESET,
      /*version=*/0, NULL, 0, NULL, 0, NULL);
}

static int command_passthrough_disable(const struct htool_invocation* inv) {
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  return htool_exec_hostcmd(
      dev, EC_CMD_BOARD_SPECIFIC_BASE + EC_PRV_CMD_HOTH_SPS_PASSTHROUGH_DISABLE,
      /*version=*/0, NULL, 0, NULL, 0, NULL);
}

static int command_passthrough_enable(const struct htool_invocation* inv) {
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  return htool_exec_hostcmd(
      dev, EC_CMD_BOARD_SPECIFIC_BASE + EC_PRV_CMD_HOTH_SPS_PASSTHROUGH_ENABLE,
      /*version=*/0, NULL, 0, NULL, 0, NULL);
}

static int command_srtm(const struct htool_invocation* inv) {
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  const char* measurement;
  if (htool_get_param_string(inv, "measurement", &measurement) != 0) {
    return -1;
  }

  struct ec_srtm_request request = {0};
  if (srtm_request_from_hex_measurement(&request, measurement) != 0) {
    return -1;
  }

  return htool_exec_hostcmd(
      dev, EC_CMD_BOARD_SPECIFIC_BASE + EC_PRV_CMD_HOTH_SRTM,
      /*version=*/0, &request, sizeof(request), NULL, 0, NULL);
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
  } else if (strcmp(transport_method_str, "dbus") == 0) {
    result = htool_libhoth_dbus_device();
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
    fprintf(stderr, "populate_ec_request_header() failed: %d\n", status);
    return -1;
  }
  status = libhoth_send_request(dev, &req, sizeof(req.hdr) + req_payload_size);
  if (status != LIBHOTH_OK) {
    fprintf(stderr, "libhoth_send_request() failed: %d\n", status);
    return -1;
  }
  struct {
    struct ec_host_response hdr;
    uint8_t payload_buf[LIBHOTH_MAILBOX_SIZE - sizeof(struct ec_host_response)];
  } resp;
  size_t resp_size;
  status = libhoth_receive_response(dev, &resp, sizeof(resp), &resp_size,
                                    /*timeout_ms=*/180000);
  if (status != LIBHOTH_OK) {
    fprintf(stderr, "libhoth_receive_response() failed: %d\n", status);
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
        .verbs = (const char*[]){"spi", "passthrough", "off", NULL},
        .desc = "Disable SPS->SPI passthrough",
        .params = (const struct htool_param[]){{}},
        .func = command_passthrough_disable,
    },
    {
        .verbs = (const char*[]){"spi", "passthrough", "on", NULL},
        .desc = "Enable SPS->SPI passthrough",
        .params = (const struct htool_param[]){{}},
        .func = command_passthrough_enable,
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
                {HTOOL_FLAG_VALUE, .name = "claim_timeout_secs",
                 .default_value = "60",
                 .desc = "How long we should attempt to claim the device "
                         "before returning a fatal error."},
                {HTOOL_FLAG_VALUE, .name = "yield_ms", .default_value = "50",
                 .desc = "After releasing the device, how long we should wait "
                         "before claiming it again. Decrease to reduce console "
                         "latency. Increase to reduce contention between "
                         "concurrent clients."},
                {}},
        .func = command_console,
    },
    {
        .verbs = (const char*[]){"payload", "getstatus", NULL},
        .desc = "Show the current payload update status",
        .params = (const struct htool_param[]){{}},
        .func = htool_payload_update_getstatus,
    },
    {
        .verbs = (const char*[]){"payload", "status", NULL},
        .desc = "Show payload status",
        .params = (const struct htool_param[]){{}},
        .func = htool_payload_status,
    },
    {
        .verbs = (const char*[]){"payload", "update", NULL},
        .desc = "Perform payload update protocol for Titan images.",
        .params =
            (const struct htool_param[]){
                {HTOOL_POSITIONAL, .name = "source-file"}, {}},
        .func = htool_payload_update,
    },
    {.verbs = (const char*[]){"flash_spi_info", NULL},
     .desc = "Get SPI NOR flash info.",
     .params = (const struct htool_param[]){{}},
     .func = command_flash_spi_info},
    {
        .verbs = (const char*[]){"statistics", NULL},
        .desc = "Show statistics",
        .params = (const struct htool_param[]){{}},
        .func = htool_statistics,
    },
    {
        .verbs = (const char*[]){"get_panic", NULL},
        .desc = "Retrieve or clear the stored panic record.",
        .params =
            (const struct htool_param[]){
                {HTOOL_FLAG_BOOL, 'c', "clear", "false",
                 .desc = "Clear the stored panic record."},
                {HTOOL_FLAG_BOOL, 'h', "hexdump", "false",
                 .desc = "Output the panic record as a hexdump."},
                {HTOOL_FLAG_VALUE, 'f', "file",
                 "", .desc = "Dump the raw panic record to a file."},
                {}},
        .func = htool_panic_get_panic,
    },
    {
        .verbs = (const char*[]){"authz_record", "read", NULL},
        .desc = "Read the current authorization record",
        .params = (const struct htool_param[]){{}},
        .func = command_authz_record_read,
    },
    {
        .verbs = (const char*[]){"authz_record", "erase", NULL},
        .desc = "Erase the current authorization record",
        .params = (const struct htool_param[]){{}},
        .func = command_authz_record_erase,
    },
    {
        .verbs = (const char*[]){"authz_record", "build", NULL},
        .desc = "Build an empty authorization record for the chip",
        .params =
            (const struct htool_param[]){
                {HTOOL_FLAG_VALUE, 'c', "caps", "0",
                 .desc = "requested capabilities"},
                {},
            },
        .func = command_authz_record_build,
    },
    {
        .verbs = (const char*[]){"authz_record", "set", NULL},
        .desc = "Upload an authorization record to the chip",
        .params =
            (const struct htool_param[]){
                {HTOOL_POSITIONAL, .name = "record"},
                {},
            },
        .func = command_authz_record_set,
    },
    {
        .verbs = (const char*[]){"arm_coordinated_reset", NULL},
        .desc = "Arms the coordinated reset to hard reset when it receives a "
                "trigger.",
        .params = (const struct htool_param[]){{}},
        .func = command_arm_coordinated_reset,
    },
    {
        .verbs = (const char*[]){"srtm", NULL},
        .desc = "Pushes a measurement into PCR0.",
        .params =
            (const struct htool_param[]){
                {HTOOL_FLAG_VALUE, 'm', "measurement", NULL,
                 .desc = "The measurement to push into PCR0. Must be a "
                         "hexidecimal string of 128 bytes or less."},
                {}},
        .func = command_srtm,
    },
    {
        .verbs = (const char*[]){"i2c", I2C_DETECT_CMD_STR, NULL},
        .desc = "Detect I2C devices on bus",
        .params =
            (const struct htool_param[]){
                {HTOOL_FLAG_VALUE, 'b', "bus", "0", .desc = "i2c bus"},
                {HTOOL_FLAG_VALUE, 's', "start", "0",
                 .desc = "7-bit start address"},
                {HTOOL_FLAG_VALUE, 'e', "end", "127",
                 .desc = "7-bit end address"},
                {}},
        .func = htool_i2c_run,
    },
    {
        .verbs = (const char*[]){"i2c", I2C_READ_CMD_STR, NULL},
        .desc = "Perform I2C transaction",
        .params =
            (const struct htool_param[]){
                {HTOOL_FLAG_VALUE, 'b', "bus", "0", .desc = "i2c bus"},
                {HTOOL_FLAG_VALUE, 'f', "frequency", "400",
                 .desc = "i2c bus frequency (100/400/1000)"},
                {HTOOL_FLAG_VALUE, 'a', "address", .desc = "start address"},
                {HTOOL_FLAG_VALUE, 'o', "offset", "-1",
                 .desc = "register offset to read"},
                {HTOOL_FLAG_BOOL, 'r', "repeated_start", "true",
                 .desc = "Use repeated start between write and read messages"
                         " when reading register from given offset"},
                {HTOOL_FLAG_VALUE, 'l', "length",
                 .desc = "how many bytes to read"},
                {}},
        .func = htool_i2c_run,
    },
    {
        .verbs = (const char*[]){"i2c", I2C_WRITE_CMD_STR, NULL},
        .desc = "Perform I2C transaction",
        .params =
            (const struct htool_param[]){
                {HTOOL_FLAG_VALUE, 'b', "bus", "0", .desc = "i2c bus"},
                {HTOOL_FLAG_VALUE, 'f', "frequency", "400",
                 .desc = "i2c bus frequency (100/400/1000)"},
                {HTOOL_FLAG_VALUE, 'a', "address", .desc = "start address"},
                {HTOOL_FLAG_VALUE, 'o', "offset", "-1",
                 .desc = "register offset to write"},
                {HTOOL_FLAG_BOOL, 'r', "no_stop", "false",
                 .desc = "don't send stop bit"},
                {HTOOL_POSITIONAL, .name = "byte_stream"},
                {}},
        .func = htool_i2c_run,
    },
    {
        .verbs = (const char*[]){"i2c", I2C_MUXCTRL_CMD_STR,
                                 I2C_MUXCTRL_GET_SUBCMD_STR, NULL},
        .desc = "Get status of I2C Mux sel (if present)",
        .params = (const struct htool_param[]){{}},
        .func = htool_i2c_muxctrl_get,
    },
    {
        .verbs = (const char*[]){"i2c", I2C_MUXCTRL_CMD_STR,
                                 I2C_MUXCTRL_SELECT_TARGET_SUBCMD_STR, NULL},
        .desc = "Change I2C Mux sel (if present) to select Target",
        .params = (const struct htool_param[]){{}},
        .func = htool_i2c_muxctrl_select_target,
    },
    {
        .verbs = (const char*[]){"i2c", I2C_MUXCTRL_CMD_STR,
                                 I2C_MUXCTRL_SELECT_HOST_SUBCMD_STR, NULL},
        .desc = "Change I2C Mux sel (if present) to select Host",
        .params = (const struct htool_param[]){{}},
        .func = htool_i2c_muxctrl_select_host,
    },
    {
        .verbs = (const char*[]){"target_usb", TARGET_USB_MUXCTRL_CMD_STR,
                                 TARGET_USB_MUXCTRL_GET_SUBCMD_STR, NULL},
        .desc = "Get status of USB mux select (if present)",
        .params = (const struct htool_param[]){{}},
        .func = htool_target_usb_muxctrl_get,
    },
    {
        .verbs = (const char*[]){"target_usb", TARGET_USB_MUXCTRL_CMD_STR,
                                 TARGET_USB_MUXCTRL_CONNECT_TARGET_TO_HOST_SUBCMD_STR, NULL},
        .desc = "Change USB mux select (if present) so that Target is connected to Host",
        .params = (const struct htool_param[]){{}},
        .func = htool_target_usb_muxctrl_connect_target_to_host,
    },
    {
        .verbs = (const char*[]){"target_usb", TARGET_USB_MUXCTRL_CMD_STR,
                                 TARGET_USB_MUXCTRL_CONNECT_TARGET_TO_FRONT_PANEL, NULL},
        .desc = "Change USB mux select (if present) so that Target is connected to Front panel",
        .params = (const struct htool_param[]){{}},
        .func = htool_target_usb_muxctrl_connect_target_to_front_panel,
    },
    {
        .verbs = (const char*[]){"raw_host_command", NULL},
        .desc = "Stream raw host commands via stdin/stdout",
        .params = (const struct htool_param[]){{}},
        .func = command_raw_host_command,
    },
    {
        .verbs = (const char*[]){"jtag", JTAG_READ_IDCODE_CMD_STR, NULL},
        .desc = "Read IDCODE for a device over JTAG. Assumes only a single "
                "device in chain",
        .params =
            (const struct htool_param[]){
                {.type = HTOOL_FLAG_VALUE,
                 .ch = 'd',
                 .name = "clk_idiv",
                 .default_value = "47",
                 .desc = "Divisor to use for JTAG clock (TCK). A value of `n` "
                         "sets the max clock rate to `(48/(n+1))` MHz. Default "
                         "value of 47 sets the clock frequency to 1MHz"},
                {}},
        .func = command_jtag_operation_run,
    },
    {
        .verbs = (const char*[]){"jtag", JTAG_TEST_BYPASS_CMD_STR, NULL},
        .desc = "Send test pattern of 64 bytes to JTAG device in BYPASS mode. "
                "Assumes only a single device in chain",
        .params =
            (const struct htool_param[]){
                {.type = HTOOL_FLAG_VALUE,
                 .ch = 'd',
                 .name = "clk_idiv",
                 .default_value = "47",
                 .desc = "Divisor to use for JTAG clock (TCK). A value of `n` "
                         "sets the max clock frequency to `(48/(n+1))` MHz. "
                         "Default value of 47 sets the clock frequency to "
                         "1MHz"},
                // Default value for `tdi_bytes` is defined where function
                // stored in `func` is defined
                {.type = HTOOL_POSITIONAL,
                 .name = "tdi_bytes",
                 // Empty string used as placeholder to detect when no
                 // value was provided at command line
                 .default_value = "",
                 .desc = "64 bytes (space separated) to send over TDI "
                         "when the JTAG device is in BYPASS mode"},
                {}},
        .func = command_jtag_operation_run,
    },
    {},
};

static const struct htool_param GLOBAL_FLAGS[] = {
    {HTOOL_FLAG_VALUE, .name = "transport", .default_value = "",
     .desc = "The method of connecting to the RoT; for example "
             "'spidev'/'usb'/'mtd'/'dbus'"},
    {HTOOL_FLAG_VALUE, .name = "usb_loc", .default_value = "",
     .desc = "The full bus-portlist location of the RoT; for example "
             "'1-10.4.4.1'."},
    {HTOOL_FLAG_VALUE, .name = "usb_product", .default_value = "",
     .desc = "If there is a single USB RoT with this substring in the USB "
             "product string, use it."},
    {HTOOL_FLAG_VALUE, .name = "spidev_path", .default_value = "",
     .desc = "The full SPIDEV path of the RoT; for example "
             "'/dev/spidev0.0'."},
    {HTOOL_FLAG_BOOL, .name = "spidev_atomic", .default_value = "false",
     .desc = "If true, force spidev to send the request and receive the "
             "corresponding response with a single atomic ioctl.  This is "
             "required on some systems for correctness."},
    {HTOOL_FLAG_VALUE, .name = "mtddev_path", .default_value = "",
     .desc = "The full MTD path of the RoT mailbox; for example "
             "'/dev/mtd0'. If unspecified, will attempt to detect "
             "the correct device automatically"},
    {HTOOL_FLAG_VALUE, .name = "mtddev_name", .default_value = "hoth-mailbox",
     .desc = "The MTD name of the RoT mailbox; for example 'hoth-mailbox'. "},
    {HTOOL_FLAG_VALUE, .name = "mailbox_location", .default_value = "0",
     .desc = "The location of the mailbox on the RoT, for 'spidev' "
             "or 'mtd' transports; for example '0x900000'."},
    {HTOOL_FLAG_VALUE, .name = "dbus_hoth_id", .default_value = "",
     .desc = "The hoth ID associated with the RoT's hothd service."},
    {HTOOL_FLAG_BOOL, .name = "version", .default_value = "false",
     .desc = "Print htool version."},
    {}};

int main(int argc, const char* const* argv) {
  return htool_main(GLOBAL_FLAGS, CMDS, argc - 1, &argv[1]);
}
