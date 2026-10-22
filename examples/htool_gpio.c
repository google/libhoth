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

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "htool_gpio.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "htool.h"
#include "htool_cmd.h"
#include "protocol/gpio_drive_strength.h"
#include "protocol/status.h"

static libhoth_error invalid_param_error(void) {
  return LIBHOTH_ERR_CONSTRUCT(HOTH_CTX_CMD_EXEC, HOTH_HOST_SPACE_LIBHOTH,
                               LIBHOTH_ERR_INVALID_PARAMETER);
}

static void trim_inplace(char* str, char** out_start) {
  char* start = str;
  while (*start && isspace((unsigned char)*start)) {
    ++start;
  }
  char* end = start + strlen(start);
  while (end > start && isspace((unsigned char)*(end - 1))) {
    --end;
  }
  *end = '\0';
  *out_start = start;
}

static bool parse_unsigned_bounded(const char* s, uint8_t max_val,
                                   uint8_t* out) {
  if (!s || !isdigit((unsigned char)s[0])) {
    return false;
  }
  errno = 0;
  char* endptr = NULL;
  unsigned long val = strtoul(s, &endptr, 10);
  if (errno != 0 || *endptr != '\0' || val > max_val) {
    return false;
  }
  *out = (uint8_t)val;
  return true;
}

static const char* const kMioPadNames[47] = {
    "MIO0",  "MIO1",  "MIO2",  "MIO3",  "MIO4",  "MIO5",  "MIO6",  "MIO7",
    "MIO8",  "MIO9",  "MIO10", "MIO11", "MIO12", "MIO13", "MIO14", "MIO15",
    "MIO16", "MIO17", "MIO18", "MIO19", "MIO20", "MIO21", "MIO22", "MIO23",
    "MIO24", "MIO25", "MIO26", "MIO27", "MIO28", "MIO29", "MIO30", "MIO31",
    "MIO32", "MIO33", "MIO34", "MIO35", "MIO36", "MIO37", "MIO38", "MIO39",
    "MIO40", "MIO41", "MIO42", "MIO43", "MIO44", "MIO45", "MIO46",
};

static const char* const kDioPadNames[16] = {
    "DIO0", "DIO1", "DIO2",  "DIO3",  "DIO4",  "DIO5",  "DIO6",  "DIO7",
    "DIO8", "DIO9", "DIO10", "DIO11", "DIO12", "DIO13", "DIO14", "DIO15",
};

libhoth_error htool_parse_spi_interface(
    const char* name, enum htool_spi_interface_id* iface_out) {
  if (!name || !iface_out) {
    return invalid_param_error();
  }
  if (strcasecmp(name, "spidev") == 0) {
    *iface_out = HTOOL_SPI_DEV;
    return HOTH_SUCCESS;
  }
  if (strcasecmp(name, "spihost0") == 0) {
    *iface_out = HTOOL_SPI_HOST0;
    return HOTH_SUCCESS;
  }
  if (strcasecmp(name, "spihost1") == 0) {
    *iface_out = HTOOL_SPI_HOST1;
    return HOTH_SUCCESS;
  }
  return invalid_param_error();
}

const char* htool_spi_interface_name(enum htool_spi_interface_id iface) {
  switch (iface) {
    case HTOOL_SPI_DEV:
      return "spidev";
    case HTOOL_SPI_HOST0:
      return "spihost0";
    case HTOOL_SPI_HOST1:
      return "spihost1";
    default:
      return "unknown";
  }
}

const char* htool_spi_signal_role_name(enum htool_spi_signal_role role) {
  switch (role) {
    case HTOOL_SPI_SIG_CLK:
      return "clk";
    case HTOOL_SPI_SIG_CS:
      return "cs";
    case HTOOL_SPI_SIG_D0:
      return "d0";
    case HTOOL_SPI_SIG_D1:
      return "d1";
    case HTOOL_SPI_SIG_D2:
      return "d2";
    case HTOOL_SPI_SIG_D3:
      return "d3";
    default:
      return "unknown";
  }
}

static bool parse_signal_role(const char* prop,
                              enum htool_spi_signal_role* role_out) {
  if (!prop || !role_out) {
    return false;
  }
  if (strcasecmp(prop, "clk") == 0) {
    *role_out = HTOOL_SPI_SIG_CLK;
    return true;
  }
  if (strcasecmp(prop, "cs") == 0) {
    *role_out = HTOOL_SPI_SIG_CS;
    return true;
  }
  if (strcasecmp(prop, "d0") == 0) {
    *role_out = HTOOL_SPI_SIG_D0;
    return true;
  }
  if (strcasecmp(prop, "d1") == 0) {
    *role_out = HTOOL_SPI_SIG_D1;
    return true;
  }
  if (strcasecmp(prop, "d2") == 0) {
    *role_out = HTOOL_SPI_SIG_D2;
    return true;
  }
  if (strcasecmp(prop, "d3") == 0) {
    *role_out = HTOOL_SPI_SIG_D3;
    return true;
  }
  return false;
}

libhoth_error htool_parse_gpio_pad(const char* token, uint8_t* pad_out) {
  if (!token || !pad_out) {
    return invalid_param_error();
  }

  char buf[64];
  size_t len = strlen(token);
  if (len == 0 || len >= sizeof(buf)) {
    return invalid_param_error();
  }
  memcpy(buf, token, len + 1);
  char* trimmed = NULL;
  trim_inplace(buf, &trimmed);
  if (*trimmed == '\0') {
    return invalid_param_error();
  }

  uint8_t idx = 0;
  if (strncasecmp(trimmed, "dio", 3) == 0) {
    if (parse_unsigned_bounded(trimmed + 3, 15, &idx)) {
      *pad_out = (uint8_t)(LIBHOTH_GPIO_DIO_PAD_OFFSET + idx);
      return HOTH_SUCCESS;
    }
    return invalid_param_error();
  }
  if (strncasecmp(trimmed, "mio", 3) == 0) {
    if (parse_unsigned_bounded(trimmed + 3, 46, &idx)) {
      *pad_out = idx;
      return HOTH_SUCCESS;
    }
    return invalid_param_error();
  }

  return invalid_param_error();
}

const char* htool_gpio_pad_name(uint8_t pad) {
  if (pad < sizeof(kMioPadNames) / sizeof(kMioPadNames[0])) {
    return kMioPadNames[pad];
  }
  if (pad >= LIBHOTH_GPIO_DIO_PAD_OFFSET) {
    uint8_t dio_idx = (uint8_t)(pad - LIBHOTH_GPIO_DIO_PAD_OFFSET);
    if (dio_idx < sizeof(kDioPadNames) / sizeof(kDioPadNames[0])) {
      return kDioPadNames[dio_idx];
    }
  }
  return "UNKNOWN_PAD";
}

static libhoth_error add_drive_strength_to_interface(
    struct htool_spi_drive_strength_interface_config* iface_cfg,
    uint8_t strength) {
  if (strength > HTOOL_MAX_TUNING_DRIVE_STRENGTH) {
    return invalid_param_error();
  }
  for (size_t i = 0; i < iface_cfg->num_drive_strengths; ++i) {
    if (iface_cfg->drive_strengths[i] == strength) {
      return HOTH_SUCCESS;
    }
  }
  if (iface_cfg->num_drive_strengths >= HTOOL_SPI_MAX_DRIVE_STRENGTHS) {
    return invalid_param_error();
  }
  iface_cfg->drive_strengths[iface_cfg->num_drive_strengths++] = strength;
  return HOTH_SUCCESS;
}

static void init_gpio_drive_strength_config(
    struct htool_gpio_drive_strength_config* config) {
  memset(config, 0, sizeof(*config));
  for (size_t i = 0; i < HTOOL_SPI_INTERFACE_COUNT; ++i) {
    memset(config->interfaces[i].pads, HTOOL_GPIO_PAD_UNMAPPED,
           sizeof(config->interfaces[i].pads));
  }
}

static libhoth_error validate_gpio_drive_strength_config(
    const struct htool_gpio_drive_strength_config* config) {
  libhoth_error err = invalid_param_error();
  for (size_t i = 0; i < HTOOL_SPI_INTERFACE_COUNT; ++i) {
    const struct htool_spi_drive_strength_interface_config* iface_cfg =
        &config->interfaces[i];
    size_t mapped_count = 0;
    for (size_t s = 0; s < HTOOL_SPI_SIGNAL_COUNT; ++s) {
      if (iface_cfg->pads[s] != HTOOL_GPIO_PAD_UNMAPPED) {
        ++mapped_count;
      }
    }
    if (mapped_count == 0 && iface_cfg->num_drive_strengths == 0) {
      continue;
    }
    const char* iface_name =
        htool_spi_interface_name((enum htool_spi_interface_id)i);
    for (size_t s = 0; s < HTOOL_SPI_SIGNAL_COUNT; ++s) {
      if (iface_cfg->pads[s] == HTOOL_GPIO_PAD_UNMAPPED) {
        fflush(stdout);
        fprintf(stderr, "Missing GPIO pad mapping for '%s.%s'.\n", iface_name,
                htool_spi_signal_role_name((enum htool_spi_signal_role)s));
        return err;
      }
    }
    if (iface_cfg->num_drive_strengths == 0) {
      fflush(stdout);
      fprintf(stderr, "Missing '%s.drive_strengths' configuration.\n",
              iface_name);
      return err;
    }
  }
  return HOTH_SUCCESS;
}

static libhoth_error parse_config_line(
    char* line, size_t line_num,
    struct htool_gpio_drive_strength_config* config) {
  for (char* p = line; *p; ++p) {
    if (*p == '#' || *p == ';') {
      *p = '\0';
      break;
    }
  }

  char* trimmed = NULL;
  trim_inplace(line, &trimmed);
  if (*trimmed == '\0') {
    return HOTH_SUCCESS;
  }

  libhoth_error inv_err = invalid_param_error();
  char* eq = strchr(trimmed, '=');
  if (!eq) {
    fflush(stdout);
    fprintf(stderr, "Config line %zu: missing '=' delimiter in '%s'.\n",
            line_num, trimmed);
    return inv_err;
  }
  *eq = '\0';
  char* key_str = NULL;
  char* val_str = NULL;
  trim_inplace(trimmed, &key_str);
  trim_inplace(eq + 1, &val_str);

  if (*key_str == '\0') {
    fflush(stdout);
    fprintf(stderr, "Config line %zu: empty key before '='.\n", line_num);
    return inv_err;
  }
  if (*val_str == '\0') {
    fflush(stdout);
    fprintf(stderr, "Config line %zu: empty value for key '%s'.\n", line_num,
            key_str);
    return inv_err;
  }

  char* dot = strchr(key_str, '.');
  if (!dot) {
    fflush(stdout);
    fprintf(stderr,
            "Config line %zu: invalid key '%s' (expected '<spi>.<property>').\n",
            line_num, key_str);
    return inv_err;
  }
  *dot = '\0';
  char* iface_name = NULL;
  char* prop_name = NULL;
  trim_inplace(key_str, &iface_name);
  trim_inplace(dot + 1, &prop_name);

  enum htool_spi_interface_id iface_id;
  libhoth_error err = htool_parse_spi_interface(iface_name, &iface_id);
  if (err != HOTH_SUCCESS) {
    fflush(stdout);
    fprintf(stderr,
            "Config line %zu: unknown SPI interface '%s' (expected spidev, "
            "spihost0, or spihost1).\n",
            line_num, iface_name);
    return err;
  }

  struct htool_spi_drive_strength_interface_config* iface_cfg =
      &config->interfaces[iface_id];
  const char* canonical_iface = htool_spi_interface_name(iface_id);

  enum htool_spi_signal_role role;
  if (parse_signal_role(prop_name, &role)) {
    if (iface_cfg->pads[role] != HTOOL_GPIO_PAD_UNMAPPED) {
      fflush(stdout);
      fprintf(stderr, "Config line %zu: duplicate key '%s.%s'.\n", line_num,
              canonical_iface, htool_spi_signal_role_name(role));
      return inv_err;
    }
    uint8_t pad = 0;
    err = htool_parse_gpio_pad(val_str, &pad);
    if (err != HOTH_SUCCESS) {
      fflush(stdout);
      fprintf(stderr,
              "Config line %zu: invalid GPIO pad '%s' for '%s.%s' (expected "
              "DIO0..DIO15 or MIO0..MIO46).\n",
              line_num, val_str, canonical_iface,
              htool_spi_signal_role_name(role));
      return err;
    }
    for (size_t i = 0; i < HTOOL_SPI_INTERFACE_COUNT; ++i) {
      for (size_t r = 0; r < HTOOL_SPI_SIGNAL_COUNT; ++r) {
        if (config->interfaces[i].pads[r] == pad) {
          fflush(stdout);
          fprintf(
              stderr,
              "Config line %zu: duplicate pad '%s' assigned to both '%s.%s' "
              "and '%s.%s'.\n",
              line_num, htool_gpio_pad_name(pad),
              htool_spi_interface_name((enum htool_spi_interface_id)i),
              htool_spi_signal_role_name((enum htool_spi_signal_role)r),
              canonical_iface, htool_spi_signal_role_name(role));
          return inv_err;
        }
      }
    }
    iface_cfg->pads[role] = pad;
    return HOTH_SUCCESS;
  }

  if (strcasecmp(prop_name, "drive_strengths") == 0) {
    if (iface_cfg->num_drive_strengths > 0) {
      fflush(stdout);
      fprintf(stderr, "Config line %zu: duplicate key '%s.drive_strengths'.\n",
              line_num, canonical_iface);
      return inv_err;
    }
    for (char* cursor = val_str; cursor != NULL;) {
      char* comma = strchr(cursor, ',');
      if (comma) {
        *comma = '\0';
      }
      char* item = NULL;
      trim_inplace(cursor, &item);
      uint8_t strength = 0;
      if (!parse_unsigned_bounded(item, HTOOL_MAX_TUNING_DRIVE_STRENGTH,
                                  &strength)) {
        fflush(stdout);
        fprintf(stderr,
                "Config line %zu: invalid drive strength '%s' for "
                "'%s.drive_strengths' (expected 0..%u).\n",
                line_num, item, canonical_iface,
                (unsigned)HTOOL_MAX_TUNING_DRIVE_STRENGTH);
        return inv_err;
      }
      err = add_drive_strength_to_interface(iface_cfg, strength);
      if (err != HOTH_SUCCESS) {
        fflush(stdout);
        fprintf(stderr,
                "Config line %zu: too many drive strengths for "
                "'%s.drive_strengths' (max %u).\n",
                line_num, canonical_iface,
                (unsigned)HTOOL_SPI_MAX_DRIVE_STRENGTHS);
        return err;
      }
      cursor = comma ? (comma + 1) : NULL;
    }
    return iface_cfg->num_drive_strengths > 0 ? HOTH_SUCCESS : inv_err;
  }

  fflush(stdout);
  fprintf(stderr,
          "Config line %zu: unknown property '%s' for SPI interface '%s' "
          "(expected clk, cs, d0..d3, or drive_strengths).\n",
          line_num, prop_name, canonical_iface);
  return inv_err;
}

libhoth_error htool_parse_gpio_drive_strength_config_str(
    const char* content, struct htool_gpio_drive_strength_config* config) {
  if (!content || !config) {
    return invalid_param_error();
  }
  init_gpio_drive_strength_config(config);

  const char* line_start = content;
  size_t line_num = 0;
  while (*line_start) {
    ++line_num;
    const char* line_end = strpbrk(line_start, "\r\n");
    size_t len =
        line_end ? (size_t)(line_end - line_start) : strlen(line_start);
    char line_buf[256];
    if (len >= sizeof(line_buf)) {
      libhoth_error err = invalid_param_error();
      fflush(stdout);
      fprintf(stderr,
              "Config line %zu: line exceeds maximum length (%zu characters).\n",
              line_num, sizeof(line_buf) - 1);
      return err;
    }
    memcpy(line_buf, line_start, len);
    line_buf[len] = '\0';

    libhoth_error err = parse_config_line(line_buf, line_num, config);
    if (err != HOTH_SUCCESS) {
      return err;
    }

    if (!line_end) {
      break;
    }
    line_start = line_end + 1;
    if (*line_end == '\r' && *line_start == '\n') {
      ++line_start;
    }
  }

  return validate_gpio_drive_strength_config(config);
}

libhoth_error htool_parse_gpio_drive_strength_config_file(
    const char* filepath, struct htool_gpio_drive_strength_config* config) {
  if (!filepath || !config) {
    return invalid_param_error();
  }
  init_gpio_drive_strength_config(config);

  FILE* fp = fopen(filepath, "r");
  if (!fp) {
    libhoth_error err = invalid_param_error();
    fflush(stdout);
    fprintf(stderr, "Cannot open configuration file '%s': %s.\n", filepath,
            strerror(errno));
    return err;
  }

  char line_buf[256];
  size_t line_num = 0;
  while (fgets(line_buf, sizeof(line_buf), fp)) {
    ++line_num;
    if (strlen(line_buf) == sizeof(line_buf) - 1 &&
        line_buf[sizeof(line_buf) - 2] != '\n') {
      int next_ch = fgetc(fp);
      if (next_ch != '\n' && next_ch != EOF) {
        libhoth_error err = invalid_param_error();
        fflush(stdout);
        fprintf(
            stderr,
            "Config line %zu: line exceeds maximum length (%zu characters).\n",
            line_num, sizeof(line_buf) - 1);
        fclose(fp);
        return err;
      }
    }
    libhoth_error err = parse_config_line(line_buf, line_num, config);
    if (err != HOTH_SUCCESS) {
      fclose(fp);
      return err;
    }
  }

  if (ferror(fp)) {
    libhoth_error err = invalid_param_error();
    fflush(stdout);
    fprintf(stderr, "Error reading configuration file '%s': %s.\n", filepath,
            strerror(errno));
    fclose(fp);
    return err;
  }

  fclose(fp);
  return validate_gpio_drive_strength_config(config);
}

static volatile sig_atomic_t g_signal_received = 0;
static volatile sig_atomic_t g_signal_pipe_write_fd = -1;

static void htool_gpio_signal_handler(int signum) {
  (void)signum;
  int saved_errno = errno;
  g_signal_received = 1;
  int fd = g_signal_pipe_write_fd;
  if (fd >= 0) {
    char b = 1;
    ssize_t unused = write(fd, &b, 1);
    (void)unused;
  }
  errno = saved_errno;
}

static bool wait_for_stdin_or_signal(int sig_pipe_read_fd) {
  while (!g_signal_received) {
    struct pollfd pfds[2];
    pfds[0].fd = STDIN_FILENO;
    pfds[0].events = POLLIN;
    pfds[0].revents = 0;
    pfds[1].fd = sig_pipe_read_fd;
    pfds[1].events = POLLIN;
    pfds[1].revents = 0;

    int rc = poll(pfds, 2, -1);
    if (g_signal_received || (rc > 0 && (pfds[1].revents & POLLIN))) {
      return false;
    }
    if (rc < 0) {
      if (errno == EINTR) {
        continue;
      }
      return false;
    }
    if (rc > 0 &&
        (pfds[0].revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL))) {
      return true;
    }
  }
  return false;
}

static bool read_prompt_line(int sig_pipe_read_fd, char* buf, size_t buf_size) {
  size_t pos = 0;
  bool got_any = false;
  while (!g_signal_received) {
    if (!wait_for_stdin_or_signal(sig_pipe_read_fd)) {
      break;
    }
    char ch = '\0';
    ssize_t n = read(STDIN_FILENO, &ch, 1);
    if (n == 1) {
      got_any = true;
      if (ch == '\n') {
        break;
      }
      if (pos + 1 < buf_size) {
        buf[pos++] = ch;
      }
    } else if (n == 0) {
      break;
    } else {
      if (errno == EINTR) {
        continue;
      }
      break;
    }
  }
  if (buf_size > 0) {
    buf[pos] = '\0';
  }
  return got_any && !g_signal_received;
}

libhoth_error htool_get_spi_interface_drive_strengths(
    struct libhoth_device* dev,
    const struct htool_spi_drive_strength_interface_config* iface_cfg,
    uint8_t strengths_out[HTOOL_SPI_SIGNAL_COUNT]) {
  if (!dev || !iface_cfg || !strengths_out) {
    return invalid_param_error();
  }
  for (size_t s = 0; s < HTOOL_SPI_SIGNAL_COUNT; ++s) {
    if (iface_cfg->pads[s] == HTOOL_GPIO_PAD_UNMAPPED) {
      return invalid_param_error();
    }
  }

  for (size_t s = 0; s < HTOOL_SPI_SIGNAL_COUNT; ++s) {
    libhoth_error err = libhoth_get_gpio_drive_strength(
        dev, iface_cfg->pads[s], &strengths_out[s]);
    if (err != HOTH_SUCCESS) {
      fflush(stdout);
      fprintf(stderr, "Error: failed to read %s (%s) drive strength\n",
              htool_spi_signal_role_name((enum htool_spi_signal_role)s),
              htool_gpio_pad_name(iface_cfg->pads[s]));
      return err;
    }
    if (strengths_out[s] > MAX_GPIO_DRIVE_STRENGTH) {
      fflush(stdout);
      fprintf(stderr,
              "Error: invalid initial drive strength %u read from %s (%s)\n",
              strengths_out[s],
              htool_spi_signal_role_name((enum htool_spi_signal_role)s),
              htool_gpio_pad_name(iface_cfg->pads[s]));
      return invalid_param_error();
    }
  }
  return HOTH_SUCCESS;
}

static libhoth_error verify_fail_error(void) {
  return LIBHOTH_ERR_CONSTRUCT(HOTH_CTX_CMD_EXEC, HOTH_HOST_SPACE_LIBHOTH,
                               LIBHOTH_ERR_FAIL);
}

static libhoth_error set_and_verify_pad_drive_strength(
    struct libhoth_device* dev, enum htool_spi_signal_role role, uint8_t pad,
    uint8_t strength, bool error_on_mismatch, uint8_t* actual_strength_out) {
  libhoth_error err = libhoth_set_gpio_drive_strength(dev, pad, strength);
  if (err != HOTH_SUCCESS) {
    return err;
  }
  uint8_t actual_strength = 0;
  err = libhoth_get_gpio_drive_strength(dev, pad, &actual_strength);
  if (err != HOTH_SUCCESS) {
    return err;
  }
  if (actual_strength_out) {
    *actual_strength_out = actual_strength;
  }
  if (actual_strength != strength) {
    fflush(stdout);
    fprintf(stderr,
            "%s: %s (%s) drive strength readback mismatch: expected %u, "
            "got %u\n",
            error_on_mismatch ? "Error" : "Warning",
            htool_spi_signal_role_name(role), htool_gpio_pad_name(pad),
            strength, actual_strength);
    if (error_on_mismatch) {
      return verify_fail_error();
    }
  }
  return HOTH_SUCCESS;
}

static libhoth_error set_spi_interface_drive_strength_with_readback(
    struct libhoth_device* dev,
    const struct htool_spi_drive_strength_interface_config* iface_cfg,
    uint8_t strength, uint8_t actual_strengths_out[HTOOL_SPI_SIGNAL_COUNT],
    bool* has_mismatch_out) {
  if (!dev || !iface_cfg || strength > HTOOL_MAX_TUNING_DRIVE_STRENGTH) {
    return invalid_param_error();
  }
  for (size_t s = 0; s < HTOOL_SPI_SIGNAL_COUNT; ++s) {
    if (iface_cfg->pads[s] == HTOOL_GPIO_PAD_UNMAPPED) {
      return invalid_param_error();
    }
  }

  bool has_mismatch = false;
  for (size_t s = 0; s < HTOOL_SPI_SIGNAL_COUNT; ++s) {
    uint8_t actual = 0;
    libhoth_error err = set_and_verify_pad_drive_strength(
        dev, (enum htool_spi_signal_role)s, iface_cfg->pads[s], strength,
        /*error_on_mismatch=*/false, &actual);
    if (err != HOTH_SUCCESS) {
      fflush(stdout);
      fprintf(stderr, "Error: failed to set %s (%s) to drive_strength=%u\n",
              htool_spi_signal_role_name((enum htool_spi_signal_role)s),
              htool_gpio_pad_name(iface_cfg->pads[s]), strength);
      return err;
    }
    if (actual_strengths_out) {
      actual_strengths_out[s] = actual;
    }
    if (actual != strength) {
      has_mismatch = true;
    }
  }
  if (has_mismatch_out) {
    *has_mismatch_out = has_mismatch;
  }
  return HOTH_SUCCESS;
}

libhoth_error htool_set_spi_interface_drive_strength(
    struct libhoth_device* dev,
    const struct htool_spi_drive_strength_interface_config* iface_cfg,
    uint8_t strength) {
  return set_spi_interface_drive_strength_with_readback(dev, iface_cfg,
                                                        strength, NULL, NULL);
}

libhoth_error htool_restore_spi_interface_drive_strengths(
    struct libhoth_device* dev,
    const struct htool_spi_drive_strength_interface_config* iface_cfg,
    const uint8_t strengths[HTOOL_SPI_SIGNAL_COUNT]) {
  if (!dev || !iface_cfg || !strengths) {
    return invalid_param_error();
  }
  for (size_t s = 0; s < HTOOL_SPI_SIGNAL_COUNT; ++s) {
    if (iface_cfg->pads[s] == HTOOL_GPIO_PAD_UNMAPPED ||
        strengths[s] > MAX_GPIO_DRIVE_STRENGTH) {
      return invalid_param_error();
    }
  }

  libhoth_error first_err = HOTH_SUCCESS;
  for (size_t s = 0; s < HTOOL_SPI_SIGNAL_COUNT; ++s) {
    libhoth_error err = set_and_verify_pad_drive_strength(
        dev, (enum htool_spi_signal_role)s, iface_cfg->pads[s], strengths[s],
        /*error_on_mismatch=*/true, NULL);
    if (err != HOTH_SUCCESS) {
      fflush(stdout);
      fprintf(stderr,
              "Error: failed to restore %s (%s) to original drive_strength=%u\n",
              htool_spi_signal_role_name((enum htool_spi_signal_role)s),
              htool_gpio_pad_name(iface_cfg->pads[s]), strengths[s]);
      if (first_err == HOTH_SUCCESS) {
        first_err = err;
      }
    }
  }
  if (first_err != HOTH_SUCCESS) {
    fflush(stdout);
    fprintf(stderr, "Original drive strengths to restore: ");
    for (size_t s = 0; s < HTOOL_SPI_SIGNAL_COUNT; ++s) {
      fprintf(stderr, "%s%s (%s)=%u", s > 0 ? ", " : "",
              htool_spi_signal_role_name((enum htool_spi_signal_role)s),
              htool_gpio_pad_name(iface_cfg->pads[s]), strengths[s]);
    }
    fprintf(stderr, "\n");
  }
  return first_err;
}

int htool_gpio_sweep(const struct htool_invocation* inv) {
  const char* config_path = NULL;
  if (htool_get_param_string(inv, "config", &config_path) || !config_path ||
      *config_path == '\0') {
    fflush(stdout);
    fprintf(stderr, "Must specify --config <path>.\n");
    return -1;
  }

  const char* spi_name = NULL;
  if (htool_get_param_string(inv, "spi", &spi_name) || !spi_name ||
      *spi_name == '\0') {
    fflush(stdout);
    fprintf(stderr, "Must specify --spi <spidev|spihost0|spihost1>.\n");
    return -1;
  }

  enum htool_spi_interface_id iface_id;
  if (htool_parse_spi_interface(spi_name, &iface_id) != HOTH_SUCCESS) {
    fflush(stdout);
    fprintf(stderr,
            "Invalid --spi value '%s'. Supported values: spidev, spihost0, "
            "spihost1.\n",
            spi_name);
    return -1;
  }

  struct htool_gpio_drive_strength_config config;
  libhoth_error err =
      htool_parse_gpio_drive_strength_config_file(config_path, &config);
  if (err != HOTH_SUCCESS) {
    return -1;
  }

  const struct htool_spi_drive_strength_interface_config* iface_cfg =
      &config.interfaces[iface_id];
  const char* canonical_name = htool_spi_interface_name(iface_id);

  if (iface_cfg->num_drive_strengths == 0) {
    fflush(stdout);
    fprintf(stderr, "SPI interface '%s' is not configured in '%s'.\n",
            canonical_name, config_path);
    return -1;
  }

  bool dry_run = false;
  if (htool_get_param_bool(inv, "dry_run", &dry_run)) {
    return -1;
  }

  const char* transport_str = NULL;
  if (iface_id == HTOOL_SPI_DEV &&
      htool_get_param_string(htool_global_flags(), "transport",
                             &transport_str) == 0 &&
      transport_str && strcasecmp(transport_str, "spidev") == 0) {
    fflush(stdout);
    fprintf(stderr,
            "Warning: sweeping 'spidev' while communicating over '--transport "
            "spidev' may disrupt host communication.\n");
  }

  int sig_pipe[2] = {-1, -1};
  if (pipe(sig_pipe) != 0) {
    fflush(stdout);
    fprintf(stderr, "Failed to create signal pipe: %s\n", strerror(errno));
    return -1;
  }
  (void)fcntl(sig_pipe[0], F_SETFL, O_NONBLOCK);
  (void)fcntl(sig_pipe[1], F_SETFL, O_NONBLOCK);
  g_signal_pipe_write_fd = sig_pipe[1];
  g_signal_received = 0;

  static const int kHandledSignals[] = {SIGINT, SIGTERM, SIGHUP};
  enum { kNumHandledSignals = 3 };

  sigset_t sig_mask;
  sigemptyset(&sig_mask);
  for (size_t s = 0; s < kNumHandledSignals; ++s) {
    sigaddset(&sig_mask, kHandledSignals[s]);
  }

  // Block signals via pthread_sigmask BEFORE opening the device so any
  // background thread spawned by the transport (e.g. libusb event thread)
  // inherits the blocked signal mask and never intercepts SIGINT/SIGTERM/SIGHUP.
  sigset_t initial_old_mask;
  pthread_sigmask(SIG_BLOCK, &sig_mask, &initial_old_mask);

  struct sigaction sa;
  struct sigaction old_sa[kNumHandledSignals];
  memset(&sa, 0, sizeof(sa));
  memset(old_sa, 0, sizeof(old_sa));
  bool sigaction_installed[kNumHandledSignals] = {false};
  sa.sa_handler = htool_gpio_signal_handler;
  sa.sa_mask = sig_mask;
  sa.sa_flags = 0;
  for (size_t s = 0; s < kNumHandledSignals; ++s) {
    sigaction_installed[s] =
        (sigaction(kHandledSignals[s], &sa, &old_sa[s]) == 0);
  }

  int ret = 0;
  struct libhoth_device* dev = NULL;
  uint8_t saved_strengths[HTOOL_SPI_SIGNAL_COUNT] = {0};
  if (!dry_run) {
    dev = htool_libhoth_device();
    if (!dev) {
      ret = -1;
      goto cleanup_signals;
    }
    err = htool_get_spi_interface_drive_strengths(dev, iface_cfg,
                                                  saved_strengths);
    if (err != HOTH_SUCCESS) {
      fflush(stdout);
      htool_report_error("get_spi_interface_drive_strengths", err);
      ret = -1;
      goto cleanup_signals;
    }
    printf("Saved original GPIO drive strengths for %s pads (", canonical_name);
    for (size_t s = 0; s < HTOOL_SPI_SIGNAL_COUNT; ++s) {
      printf("%s%s [%s]=%u", s > 0 ? ", " : "",
             htool_spi_signal_role_name((enum htool_spi_signal_role)s),
             htool_gpio_pad_name(iface_cfg->pads[s]), saved_strengths[s]);
    }
    printf(").\n");
    fflush(stdout);
  }

  pthread_sigmask(SIG_SETMASK, &initial_old_mask, NULL);

  bool completed = true;
  for (size_t i = 0; i < iface_cfg->num_drive_strengths; ++i) {
    if (g_signal_received) {
      printf("\nSweep interrupted by signal.\n");
      fflush(stdout);
      ret = -1;
      completed = false;
      break;
    }

    uint8_t strength = iface_cfg->drive_strengths[i];
    uint8_t actual_strengths[HTOOL_SPI_SIGNAL_COUNT] = {0};
    bool has_mismatch = false;
    if (!dry_run) {
      sigset_t step_old_mask;
      pthread_sigmask(SIG_BLOCK, &sig_mask, &step_old_mask);
      err = set_spi_interface_drive_strength_with_readback(
          dev, iface_cfg, strength, actual_strengths, &has_mismatch);
      pthread_sigmask(SIG_SETMASK, &step_old_mask, NULL);
      if (err != HOTH_SUCCESS) {
        fflush(stdout);
        htool_report_error("set_spi_interface_drive_strength", err);
        ret = -1;
        completed = false;
        break;
      }
    }

    printf("%s[%zu/%zu] %s drive_strength=%u to %s pads (",
           dry_run ? "[Dry Run] " : "", i + 1, iface_cfg->num_drive_strengths,
           has_mismatch ? "Applied (with readback mismatch)" : "Applied",
           strength, canonical_name);
    for (size_t s = 0; s < HTOOL_SPI_SIGNAL_COUNT; ++s) {
      if (dry_run) {
        printf("%s%s [%s]", s > 0 ? ", " : "",
               htool_spi_signal_role_name((enum htool_spi_signal_role)s),
               htool_gpio_pad_name(iface_cfg->pads[s]));
      } else {
        printf("%s%s [%s]=%u", s > 0 ? ", " : "",
               htool_spi_signal_role_name((enum htool_spi_signal_role)s),
               htool_gpio_pad_name(iface_cfg->pads[s]), actual_strengths[s]);
      }
    }
    printf(").\n");
    fflush(stdout);

    if (g_signal_received) {
      printf("\nSweep interrupted by signal.\n");
      fflush(stdout);
      ret = -1;
      completed = false;
      break;
    }

    printf(
        "Trigger SPI traffic and capture signals now. Press Enter for next "
        "combination (or 'q' + Enter to quit): ");
    fflush(stdout);

    char input_buf[64];
    if (!read_prompt_line(sig_pipe[0], input_buf, sizeof(input_buf))) {
      printf("\n");
      if (g_signal_received) {
        printf("Sweep interrupted by signal.\n");
        ret = -1;
      }
      fflush(stdout);
      completed = false;
      break;
    }
    const char* p = input_buf;
    while (*p == ' ' || *p == '\t') {
      ++p;
    }
    if (*p == 'q' || *p == 'Q') {
      printf("Sweep aborted by user.\n");
      fflush(stdout);
      completed = false;
      break;
    }
  }

  if (completed) {
    printf("GPIO drive strength sweep completed.\n");
    fflush(stdout);
  }

  pthread_sigmask(SIG_BLOCK, &sig_mask, NULL);

  if (!dry_run) {
    err = htool_restore_spi_interface_drive_strengths(dev, iface_cfg,
                                                      saved_strengths);
    if (err != HOTH_SUCCESS) {
      fflush(stdout);
      htool_report_error("restore_spi_interface_drive_strengths", err);
      ret = -1;
    } else {
      printf("Restored original GPIO drive strengths for %s pads (",
             canonical_name);
      for (size_t s = 0; s < HTOOL_SPI_SIGNAL_COUNT; ++s) {
        printf("%s%s [%s]=%u", s > 0 ? ", " : "",
               htool_spi_signal_role_name((enum htool_spi_signal_role)s),
               htool_gpio_pad_name(iface_cfg->pads[s]), saved_strengths[s]);
      }
      printf(").\n");
      fflush(stdout);
    }
  } else {
    printf("[Dry Run] Restored original GPIO drive strengths for %s pads.\n",
           canonical_name);
    fflush(stdout);
  }

cleanup_signals:
  pthread_sigmask(SIG_SETMASK, &initial_old_mask, NULL);
  for (size_t s = 0; s < kNumHandledSignals; ++s) {
    if (sigaction_installed[s]) {
      sigaction(kHandledSignals[s], &old_sa[s], NULL);
    }
  }
  g_signal_pipe_write_fd = -1;
  close(sig_pipe[0]);
  close(sig_pipe[1]);
  if (g_signal_received) {
    ret = -1;
  }

  return ret;
}
