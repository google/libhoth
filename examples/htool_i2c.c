// Copyright 2024 Google LLC
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

#include "htool_i2c.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "host_commands.h"
#include "htool.h"
#include "htool_cmd.h"
#include "htool_target_control.h"

static int i2c_detect(struct libhoth_device *dev,
                      const struct htool_invocation *inv) {
  uint32_t bus;
  uint32_t start_addr;
  uint32_t end_addr;

  if (htool_get_param_u32(inv, "bus", &bus) ||
      htool_get_param_u32(inv, "start", &start_addr) ||
      htool_get_param_u32(inv, "end", &end_addr)) {
    return -1;
  }

  struct ec_request_i2c_detect request;
  request.bus_number = (uint8_t)(bus & 0xFF);
  request.start_address = (uint8_t)(start_addr & 0x7F);
  request.end_address = (uint8_t)(end_addr & 0x7F);

  uint8_t response[sizeof(struct ec_response_i2c_detect)];
  size_t rLen = 0;
  int ret = htool_exec_hostcmd(
      dev, EC_CMD_BOARD_SPECIFIC_BASE + EC_PRV_CMD_HOTH_I2C_DETECT, 0, &request,
      sizeof(request), &response, sizeof(response), &rLen);
  if (ret != 0) {
    fprintf(stderr, "HOTH_I2C_DETECT error code: %d\n", ret);
    return -1;
  }
  if (rLen != sizeof(response)) {
    fprintf(stderr,
            "HOTH_I2C_DETECT expected exactly %ld response "
            "bytes, got %ld\n",
            sizeof(response), rLen);
    return -1;
  }

  struct ec_response_i2c_detect *pI2d =
      (struct ec_response_i2c_detect *)(response);

  printf("Detected %u devices on bus.\n", pI2d->devices_count);
  if (pI2d->devices_count) {
    for (uint8_t i = 0; i < I2C_DETECT_DATA_MAX_SIZE_BYTES; i++) {
      for (uint8_t b = 0; b < 8; b++) {
        if (pI2d->devices_mask[i] & (1 << b)) {
          printf("0x%02X ", (i * 8 + b));
        }
      }
    }
    printf("\n");
  }

  return 0;
}

static int i2c_read(struct libhoth_device *dev,
                    const struct htool_invocation *inv) {
  uint32_t bus;
  uint32_t freq;
  uint32_t addr;
  uint32_t offset;
  uint32_t length;
  bool repeated_start;

  if (htool_get_param_u32(inv, "bus", &bus) ||
      htool_get_param_u32(inv, "frequency", &freq) ||
      htool_get_param_u32(inv, "address", &addr) ||
      htool_get_param_u32(inv, "offset", &offset) ||
      htool_get_param_u32(inv, "length", &length) ||
      htool_get_param_bool(inv, "repeated_start", &repeated_start)) {
    return -1;
  }

  struct ec_request_i2c_transfer request;
  request.bus_number = (uint8_t)(bus & 0xFF);
  request.dev_address = (uint8_t)(addr & 0x7F);
  request.size_read = (uint16_t)(length & 0xFFFF);
  request.speed_khz = (uint16_t)(freq & 0xFFFF);
  request.flags = (repeated_start ? I2C_BITS_REPEATED_START : 0);

  if (offset == UINT32_MAX) {
    request.size_write = 0;
  } else {
    request.size_write = 1;
    request.arg_bytes[0] = (offset & 0xFF);
  }

  uint8_t response[sizeof(struct ec_response_i2c_transfer)];
  size_t rLen = 0;
  int ret = htool_exec_hostcmd(
      dev, EC_CMD_BOARD_SPECIFIC_BASE + EC_PRV_CMD_HOTH_I2C_TRANSFER, 0,
      &request, sizeof(request), &response, sizeof(response), &rLen);
  if (ret != 0) {
    fprintf(stderr, "HOTH_I2C_TRANSFER [read] error code: %d\n", ret);
    return -1;
  }
  if (rLen != sizeof(response)) {
    fprintf(stderr,
            "HOTH_I2C_TRANSFER [read] expected exactly %ld response "
            "bytes, got %ld\n",
            sizeof(response), rLen);
    return -1;
  }

  struct ec_response_i2c_transfer *pI2t =
      (struct ec_response_i2c_transfer *)(response);

  if (offset != UINT32_MAX) {
    printf("Read %u bytes from I2C device %u:0x%02x offset: 0x%02x\n",
           pI2t->read_bytes, request.bus_number, request.dev_address,
           offset & 0xFF);
  } else {
    printf("Read %u bytes from I2C device %u:0x%02x\n", pI2t->read_bytes,
           request.bus_number, request.dev_address);
  }
  for (uint16_t i = 0; i < pI2t->read_bytes; i++) {
    printf("0x%02X ", pI2t->resp_bytes[i]);
  }
  printf("\n");

  return 0;
}

static int i2c_write(struct libhoth_device *dev,
                     const struct htool_invocation *inv) {
  uint32_t bus;
  uint32_t freq;
  uint32_t addr;
  uint32_t offset;
  bool no_stop;
  char *byte_stream = NULL;

  if (htool_get_param_u32(inv, "bus", &bus) ||
      htool_get_param_u32(inv, "frequency", &freq) ||
      htool_get_param_u32(inv, "address", &addr) ||
      htool_get_param_u32(inv, "offset", &offset) ||
      htool_get_param_bool(inv, "no_stop", &no_stop) ||
      htool_get_param_string(inv, "byte_stream", (const char **)&byte_stream)) {
    return -1;
  }

  if (byte_stream == NULL) {
    return -1;
  }

  struct ec_request_i2c_transfer request;
  request.bus_number = (uint8_t)(bus & 0xFF);
  request.dev_address = (uint8_t)(addr & 0x7F);
  request.speed_khz = (uint16_t)(freq & 0xFFFF);
  request.flags = (no_stop ? I2C_BITS_NO_STOP : 0) | I2C_BITS_WRITE;
  request.size_read = 0;

  uint16_t idx = 0;

  if (offset != UINT32_MAX) {
    request.arg_bytes[idx++] = (uint8_t)(offset & 0xFF);
  }

  char *tk = strtok(byte_stream, " ");
  while (tk && (idx < I2C_TRANSFER_DATA_MAX_SIZE_BYTES)) {
    char *endptr;
    unsigned long int parsed = strtoul(tk, &endptr, 0);
    if (tk == endptr || parsed > UINT8_MAX || *endptr != '\0') {
      fprintf(stderr, "Invalid input data.\n");
      return -1;
    }
    request.arg_bytes[idx++] = (uint8_t)parsed;
    tk = strtok(NULL, " ");
  }
  request.size_write = idx;

  uint8_t response[sizeof(struct ec_response_i2c_transfer)];
  size_t rLen = 0;
  int ret = htool_exec_hostcmd(
      dev, EC_CMD_BOARD_SPECIFIC_BASE + EC_PRV_CMD_HOTH_I2C_TRANSFER, 0,
      &request, sizeof(request), &response, sizeof(response), &rLen);
  if (ret != 0) {
    fprintf(stderr, "HOTH_I2C_TRANSFER [write] error code: %d\n", ret);
    return -1;
  }
  if (rLen != sizeof(response)) {
    fprintf(stderr,
            "HOTH_I2C_TRANSFER [write] expected exactly %ld response "
            "bytes, got %ld\n",
            sizeof(response), rLen);
    return -1;
  }

  if (offset != UINT32_MAX) {
    assert(request.size_write >= 1);
    printf("Wrote %u bytes to I2C device %u:0x%02x at offset: 0x%02x\n",
           request.size_write - 1, request.bus_number, request.dev_address,
           offset & 0xFF);
  } else {
    printf("Wrote %u bytes to I2C device %u:0x%02x\n", request.size_write,
           request.bus_number, request.dev_address);
  }

  struct ec_response_i2c_transfer *pI2t =
      (struct ec_response_i2c_transfer *)(response);
  if (pI2t->bus_response) {
    fprintf(stderr, "HOTH_I2C_TRANSFER [write] bus error: %d\n",
            pI2t->bus_response);
  }

  return 0;
}

int htool_i2c_run(const struct htool_invocation *inv) {
  struct libhoth_device *dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  if (strncmp(inv->cmd->verbs[1], I2C_DETECT_CMD_STR,
              sizeof(I2C_DETECT_CMD_STR)) == 0) {
    return i2c_detect(dev, inv);
  } else if (strncmp(inv->cmd->verbs[1], I2C_READ_CMD_STR,
                     sizeof(I2C_READ_CMD_STR)) == 0) {
    return i2c_read(dev, inv);
  } else if (strncmp(inv->cmd->verbs[1], I2C_WRITE_CMD_STR,
                     sizeof(I2C_WRITE_CMD_STR)) == 0) {
    return i2c_write(dev, inv);
  }

  return -1;
}

// I2C mux control actions to Target control actions mapping
enum {
  I2C_MUXCTRL_ACTION_GET = EC_TARGET_CONTROL_ACTION_GET_STATUS,
  I2C_MUXCTRL_ACTION_SELECT_TARGET = EC_TARGET_CONTROL_ACTION_ENABLE,
  I2C_MUXCTRL_ACTION_SELECT_HOST = EC_TARGET_CONTROL_ACTION_DISABLE,
};

// Target control status to I2C mux control status mapping
static const char *i2c_muxctrl_status_str_map(
    const enum ec_target_control_status status) {
  switch (status) {
    case EC_TARGET_CONTROL_STATUS_ENABLED:
      return "Target";
    case EC_TARGET_CONTROL_STATUS_DISABLED:
      return "Host";
    default:
      return "Unknown";
  }
}

int htool_i2c_muxctrl_get(const struct htool_invocation *inv) {
  struct ec_response_target_control response;
  int ret = target_control_perform_action(EC_TARGET_CONTROL_I2C_MUX,
                                          I2C_MUXCTRL_ACTION_GET, &response);
  if (ret != 0) {
    return ret;
  }

  printf("I2C Mux control status: %s\n",
         i2c_muxctrl_status_str_map(response.status));
  return 0;
}

static int i2c_mux_control_change_select(
    const enum ec_target_control_action action) {
  struct ec_response_target_control response;
  int ret = target_control_perform_action(EC_TARGET_CONTROL_I2C_MUX, action,
                                          &response);
  if (ret != 0) {
    return ret;
  }
  const enum ec_target_control_status old_status = response.status;

  ret = target_control_perform_action(EC_TARGET_CONTROL_I2C_MUX,
                                      I2C_MUXCTRL_ACTION_GET, &response);
  if (ret != 0) {
    return ret;
  }
  const enum ec_target_control_status new_status = response.status;

  printf("I2C Mux control status changed: %s -> %s\n",
         i2c_muxctrl_status_str_map(old_status),
         i2c_muxctrl_status_str_map(new_status));
  return 0;
}

int htool_i2c_muxctrl_select_target(const struct htool_invocation *inv) {
  return i2c_mux_control_change_select(I2C_MUXCTRL_ACTION_SELECT_TARGET);
}

int htool_i2c_muxctrl_select_host(const struct htool_invocation *inv) {
  return i2c_mux_control_change_select(I2C_MUXCTRL_ACTION_SELECT_HOST);
}
