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

#include <libusb-1.0/libusb.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "bind.h"
#include "libhoth_usb.h"

const char *usage = "enumerate <bus number> <device address>\n";

int main(int argc, char **argv) {
  if (argc != 3) {
    fprintf(stderr, "Invalid arguments.\n");
    fprintf(stderr, "Usage:\n\t%s", usage);
    return -1;
  }
  uint8_t bus, address;
  char *endptr;
  bus = strtoul(argv[1], &endptr, 0);
  if (endptr == argv[1] || *endptr != '\0') {
    fprintf(stderr, "Failed to parse bus number.\n");
    fprintf(stderr, "Usage:\n\t%s", usage);
    return -1;
  }
  address = strtoul(argv[2], &endptr, 0);
  if (endptr == argv[2] || *endptr != '\0') {
    fprintf(stderr, "Failed to parse device address.\n");
    fprintf(stderr, "Usage:\n\t%s", usage);
    return -1;
  }

  struct libhoth_usb_device *dev = NULL;
  int status = hoth_usb_probe(&dev, bus, address, /*verbose=*/true);
  if (status != LIBHOTH_OK) {
    fprintf(stderr, "probe() failed: %d\n", status);
    return status;
  }

  status = hoth_usb_remove(dev, /*verbose=*/true);
  if (status != LIBHOTH_OK) {
    fprintf(stderr, "remove() failed: %d\n", status);
    return status;
  }
  printf("ALL OK.\n");
  return 0;
}
