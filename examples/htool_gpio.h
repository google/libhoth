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

#ifndef LIBHOTH_EXAMPLES_HTOOL_GPIO_H_
#define LIBHOTH_EXAMPLES_HTOOL_GPIO_H_

#include <stddef.h>
#include <stdint.h>

#include "protocol/gpio_drive_strength.h"
#include "protocol/status.h"

#ifdef __cplusplus
extern "C" {
#endif

struct htool_invocation;
struct libhoth_device;

#define HTOOL_SPI_MAX_DRIVE_STRENGTHS 4
#define HTOOL_MAX_TUNING_DRIVE_STRENGTH 3

// Sentinel value indicating that an SPI signal role is not mapped to any pad.
#define HTOOL_GPIO_PAD_UNMAPPED 0xFF

// Target SPI controllers supported by GPIO drive strength tuning.
enum htool_spi_interface_id {
  HTOOL_SPI_DEV = 0,
  HTOOL_SPI_HOST0 = 1,
  HTOOL_SPI_HOST1 = 2,
  HTOOL_SPI_INTERFACE_COUNT = 3,
};

// Required signal roles within an SPI interface.
enum htool_spi_signal_role {
  HTOOL_SPI_SIG_CLK = 0,
  HTOOL_SPI_SIG_CS = 1,
  HTOOL_SPI_SIG_D0 = 2,
  HTOOL_SPI_SIG_D1 = 3,
  HTOOL_SPI_SIG_D2 = 4,
  HTOOL_SPI_SIG_D3 = 5,
  HTOOL_SPI_SIGNAL_COUNT = 6,
};

// GPIO pad mappings and supported drive strength values for a single SPI
// controller. All 6 signal roles (clk, cs, d0..d3) must be mapped for a
// configured SPI interface.
struct htool_spi_drive_strength_interface_config {
  // Pad assigned to each signal role (indexed by enum htool_spi_signal_role),
  // or HTOOL_GPIO_PAD_UNMAPPED (0xFF) if unmapped.
  uint8_t pads[HTOOL_SPI_SIGNAL_COUNT];
  // Supported drive strength values (0..3) to sweep.
  uint8_t drive_strengths[HTOOL_SPI_MAX_DRIVE_STRENGTHS];
  size_t num_drive_strengths;
};

// Complete GPIO drive strength tuning configuration across all SPI controllers.
struct htool_gpio_drive_strength_config {
  struct htool_spi_drive_strength_interface_config
      interfaces[HTOOL_SPI_INTERFACE_COUNT];
};

// Parses a case-insensitive SPI interface name ("spidev", "spihost0",
// "spihost1") into `iface_out`.
libhoth_error htool_parse_spi_interface(const char* name,
                                        enum htool_spi_interface_id* iface_out);

// Returns a static null-terminated string literal for `iface` ("spidev",
// "spihost0", "spihost1", or "unknown").
const char* htool_spi_interface_name(enum htool_spi_interface_id iface);

// Returns a static null-terminated string literal for `role` ("clk", "cs",
// "d0".."d3", or "unknown").
const char* htool_spi_signal_role_name(enum htool_spi_signal_role role);

// Parses a GPIO pad specifier ("DIO0".."DIO15" or "MIO0".."MIO46",
// case-insensitive) into an encoded pad ID in `pad_out`.
libhoth_error htool_parse_gpio_pad(const char* token, uint8_t* pad_out);

// Returns a static null-terminated string literal representing `pad`
// ("DIO0".."DIO15", "MIO0".."MIO46", or "UNKNOWN_PAD").
const char* htool_gpio_pad_name(uint8_t pad);

// Parses a null-terminated configuration string into `config`.
libhoth_error htool_parse_gpio_drive_strength_config_str(
    const char* content, struct htool_gpio_drive_strength_config* config);

// Reads and parses a configuration file at `filepath` into `config`.
libhoth_error htool_parse_gpio_drive_strength_config_file(
    const char* filepath, struct htool_gpio_drive_strength_config* config);

// Reads the current GPIO drive strength for each of the 6 configured pads in
// `iface_cfg` into `strengths_out`.
libhoth_error htool_get_spi_interface_drive_strengths(
    struct libhoth_device* dev,
    const struct htool_spi_drive_strength_interface_config* iface_cfg,
    uint8_t strengths_out[HTOOL_SPI_SIGNAL_COUNT]);

// Applies `strength` (0..3) uniformly across all 6 configured pads in
// `iface_cfg`, reading back each pad after setting it and warning on stderr if
// the readback value does not match `strength`.
libhoth_error htool_set_spi_interface_drive_strength(
    struct libhoth_device* dev,
    const struct htool_spi_drive_strength_interface_config* iface_cfg,
    uint8_t strength);

// Restores per-pad GPIO drive strengths (`strengths[0..5]`) across all 6
// configured pads in `iface_cfg`, reading back each pad and treating a
// readback mismatch as an error. Attempts all 6 pads even if an earlier pad
// fails, returning the first error encountered (or HOTH_SUCCESS).
libhoth_error htool_restore_spi_interface_drive_strengths(
    struct libhoth_device* dev,
    const struct htool_spi_drive_strength_interface_config* iface_cfg,
    const uint8_t strengths[HTOOL_SPI_SIGNAL_COUNT]);

// CLI handler for `htool gpio sweep`.
int htool_gpio_sweep(const struct htool_invocation* inv);

#ifdef __cplusplus
}
#endif

#endif  // LIBHOTH_EXAMPLES_HTOOL_GPIO_H_
