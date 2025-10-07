#include "htool_provisioning.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "host_commands.h"
#include "htool.h"
#include "htool_cmd.h"
#include "htool_macros.h"
#include "htool_security_version.h"
#include "protocol/host_cmd.h"

// This is a standalone CRC32 that matches Titan Firmware.
// A table-free bit-level implementation is okay since there are no
// performance constraints in it's use in htool_validate_and_sign.
uint32_t crc32(uint32_t initial_value, const uint8_t *buf, size_t size) {
  const uint32_t polynomial = 0xEDB88320;

  uint32_t crc = ~initial_value;
  for (int i = 0; i < size; i++) {
    uint8_t byte = ((uint8_t *)buf)[i];
    crc = crc ^ byte;
    for (int j = 0; j < 8; j++, byte >>= 1) {
      crc = (crc >> 1) ^ ((crc & 1) ? polynomial : 0);
    }
  }
  return ~crc;
}

static uint16_t min(uint16_t a, uint16_t b) { return (a < b) ? a : b; }

int htool_get_provisioning_log(const struct htool_invocation* inv) {
  int status = -1;
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    printf("libhoth_device was not found\n");
    return -1;
  }

  const char* output_file;
  if (htool_get_param_string(inv, "output", &output_file) != 0) {
    printf("There was an error getting the output parameter\n");
    return -1;
  }

  FILE* output_ptr = NULL;
  output_ptr = fopen(output_file, "wb");
  if (output_ptr == NULL) {
    printf("There was an error opening file: %s\n", output_file);
    goto cleanup;
  }
  enum provisioning_log_op operation = PROVISIONING_LOG_READ;

  struct hoth_provisioning_log_header prov_log_hdr_resp;
  memset(&prov_log_hdr_resp, 0, sizeof(prov_log_hdr_resp));
  struct hoth_provisioning_log_request request = {
      .version = 1,
      .operation = operation,
      .reserved = 0,
      .offset = 0,
      .size = 0,
      .checksum = 0,
  };

  libhoth_security_version sv = htool_get_security_version(dev);
  switch (sv) {
    case LIBHOTH_SECURITY_V2: {
      {
        // Get Provisioning Log Header
        size_t response_size = 0;
        uint8_t* request_ptr = (uint8_t*)&request;
        int exec_status = libhoth_hostcmd_exec(
            dev, /*command=*/HOTH_BASE_CMD(HOTH_PRV_CMD_HOTH_PROVISIONING_LOG),
            /*version=*/0, request_ptr, sizeof(request), &prov_log_hdr_resp,
            sizeof(prov_log_hdr_resp), &response_size);
        if (exec_status != 0) {
          status = exec_status;
          goto cleanup;
        }
        uint16_t bytes_read = 0;
        // Holds the provisioning log data while all of the chunks are being
        // collected
        uint8_t provisioning_log_data[PROVISIONING_LOG_MAX_SIZE];
        // Get Provisioning Log
        while (bytes_read < prov_log_hdr_resp.size) {
          struct hoth_provisioning_log response;
          memset(&response, 0, sizeof(response));
          // Get the size of the data to be requested
          uint16_t chunk_size = min(prov_log_hdr_resp.size - bytes_read,
                                    PROVISIONING_LOG_CHUNK_MAX_SIZE);
          // Update the request to the appropriate size
          request.offset = bytes_read;
          request.size = chunk_size;
          response_size = 0;

          // Execute libhoth command
          exec_status = libhoth_hostcmd_exec(
              dev,
              /*command=*/HOTH_BASE_CMD(HOTH_PRV_CMD_HOTH_PROVISIONING_LOG),
              /*version=*/0, &request, sizeof(request), &response,
              sizeof(response), &response_size);
          if (exec_status != 0) {
            printf(
                "Unexpected error returned while trying to send command to "
                "read the provisioning_log\n");
            status = exec_status;
            goto cleanup;
          }
          // Check if read bytes matches chunk size
          if (response_size != chunk_size + sizeof(prov_log_hdr_resp)) {
            printf(
                "Unexpected host command response size. Expecting %lu; Got "
                "%lu\n",
                chunk_size + sizeof(prov_log_hdr_resp), response_size);
            status = 1;
            goto cleanup;
          }

          if (bytes_read + chunk_size > PROVISIONING_LOG_MAX_SIZE) {
            printf(
                "Unexpected Error: Bytes returned: %hu > "
                "PROVISIONING_LOG_MAX_SIZE: %u\n",
                bytes_read + chunk_size, PROVISIONING_LOG_MAX_SIZE);
            goto cleanup;
          }

          // Copy the read bytes into the provisioning_log_data buffer
          memcpy(provisioning_log_data + bytes_read, response.data,
                 chunk_size);
          // Increment the amount of bytes of the provisioning_log that have
          // been consumed
          bytes_read += chunk_size;
        }
        // Write the provisioning_log that was read into the output file
        fwrite(provisioning_log_data, bytes_read, sizeof(uint8_t), output_ptr);
        break;
      }
    }
    // SECURITY_V3 not supported yet.
    default:
      status = -1;
      printf("SECURITY_V3 is not supported yet\n");
      goto cleanup;
  }

  // Return success if no other errors have occured at this point
  status = 0;  // Success

cleanup:
  if (output_ptr) {
    if (fclose(output_ptr) != 0) {
      printf("There was an issue closing the output file: %s\n", output_file);
    }
  }
  return status;
}

int htool_validate_and_sign(const struct htool_invocation* inv) {
  int status = -1;
  FILE* perso_blob_ptr = NULL;
  FILE* output_ptr = NULL;
  uint8_t* perso_blob_data = NULL;
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    printf("libhoth_device was not found\n");
    return -1;
  }

  const char* perso_blob_file;
  if (htool_get_param_string(inv, "perso_blob", &perso_blob_file) != 0) {
    printf("There was an error getting the perso_blob parameter\n");
    return -1;
  }

  perso_blob_ptr = fopen(perso_blob_file, "rb");
  if (perso_blob_ptr == NULL) {
    printf("There was an error opening file: %s\n", perso_blob_file);
    goto cleanup;
  }

  fseek(perso_blob_ptr, 0, SEEK_END);
  uint32_t perso_blob_size = ftell(perso_blob_ptr);
  rewind(perso_blob_ptr);

  perso_blob_data = (uint8_t*)malloc(perso_blob_size);
  size_t bytes_read =
      fread(perso_blob_data, sizeof(uint8_t), perso_blob_size, perso_blob_ptr);
  if (bytes_read <= 0) {
    printf(
            "There was an error reading the input file to a byte array: %s\n",
            perso_blob_file);
    goto cleanup;
  }

  const char* output_file;
  if (htool_get_param_string(inv, "output", &output_file) != 0) {
    printf("There was an error getting the output parameter\n");
    goto cleanup;
  }

  output_ptr = fopen(output_file, "wb");
  if (output_ptr == NULL) {
    printf("There was an error opening file: %s\n", output_file);
    goto cleanup;
  }

  enum provisioning_log_op operation = PROVISIONING_LOG_VALIDATE_AND_SIGN;

  // Collect all of the bytes from the request
  uint8_t response[PROVISIONING_CERT_MAX_SIZE];
  memset(response, 0, sizeof(response));
  uint32_t checksum = crc32(0, perso_blob_data, perso_blob_size);
  struct hoth_provisioning_log_request request = {
      .version = 1,
      .operation = operation,
      .reserved = 0,
      .offset = 0,
      .size = perso_blob_size,
      .checksum = checksum,
  };

  libhoth_security_version sv = htool_get_security_version(dev);
  switch (sv) {
    case LIBHOTH_SECURITY_V2: {
      {
        // Validate and Sign the Provisioning Log
        size_t response_size = 0;
        uint8_t* request_ptr = (uint8_t*)&request;
        int exec_status = libhoth_hostcmd_exec(
            dev, /*command=*/HOTH_BASE_CMD(HOTH_PRV_CMD_HOTH_PROVISIONING_LOG),
            /*version=*/0, request_ptr, sizeof(request), &response,
            sizeof(response), &response_size);
        if (exec_status != 0) {
          status = exec_status;
          goto cleanup;
        }

        if (response_size > PROVISIONING_CERT_MAX_SIZE) {
          printf(
              "Unexpected Error: Bytes returned: %lu > "
              "PROVISIONING_CERT_MAX_SIZE: %u\n",
              response_size, PROVISIONING_CERT_MAX_SIZE);
          goto cleanup;
        }

        // Write the signed provisioning_log into the output file
        fwrite(response, response_size, sizeof(uint8_t), output_ptr);
        break;
      }
    }
    // SECURITY_V3 not supported yet.
    default:
      status = -1;
      printf("SECURITY_V3 is not supported yet.\n");
      goto cleanup;
  }

  // Return success if no other errors have occured at this point
  status = 0;  // Success

cleanup:
  if (output_ptr) {
    if (fclose(output_ptr) != 0) {
      printf("There was an issue closing the output file: %s\n", output_file);
    }
  }
  if (perso_blob_ptr) {
    if (fclose(perso_blob_ptr) != 0) {
      printf("There was an issue closing the perso blob file: %s\n", perso_blob_file);
    }
  }
  if (perso_blob_data) {
    free(perso_blob_data);
  }
  return status;
}
