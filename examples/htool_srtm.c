#include "htool_srtm.h"

#include <stdio.h>
#include <string.h>

#include "host_commands.h"

int srtm_request_from_hex_measurement(struct hoth_srtm_request* request,
                                      const char* measurement) {
  size_t hex_length = strlen(measurement);
  if (hex_length == 0) {
    fprintf(stderr, "Must provide a measurement.\n");
    return -1;
  }
  if (hex_length % 2 == 1) {
    fprintf(stderr, "Measurement must have an even byte size, got %lu bytes\n",
            hex_length);
    return -1;
  }
  if (hex_length > SRTM_DATA_MAX_SIZE_BYTES * 2) {
    fprintf(stderr, "Measurement cannot surpass %d bytes, got %lu bytes\n",
            SRTM_DATA_MAX_SIZE_BYTES * 2, hex_length);
    return -1;
  }

  for (int i = 0; i < hex_length; i += 2) {
    unsigned int first_nibble;
    unsigned int second_nibble;

    // We don't use the %02X matcher to match a whole byte, because
    // it will still succeed if one of the hex digits is invalid.
    if (sscanf(measurement + i, "%01X", &first_nibble) != 1) {
      fprintf(stderr, "Invalid hex digit: %c\n", measurement[i]);
      return -1;
    }
    if (sscanf(measurement + i + 1, "%01X", &second_nibble) != 1) {
      fprintf(stderr, "Invalid hex digit: %c\n", measurement[i + 1]);
      return -1;
    }
    request->data[i / 2] = (first_nibble << 4) | second_nibble;
  }
  request->data_size = (hex_length / 2);
  return 0;
}
