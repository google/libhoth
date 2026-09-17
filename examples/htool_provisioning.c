#include "htool_provisioning.h"

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "host_commands.h"
#include "htool.h"
#include "htool_cmd.h"
#include "htool_security_version.h"
#include "protocol/host_cmd.h"
#include "transports/libhoth_device.h"

// This is a standalone CRC32 that matches Titan Firmware.
// A table-free bit-level implementation is okay since there are no
// performance constraints in it's use in htool_validate_and_sign.
uint32_t crc32(uint32_t initial_value, const uint8_t* buf, size_t size) {
  const uint32_t polynomial = 0xEDB88320;

  uint32_t crc = ~initial_value;
  for (int i = 0; i < size; i++) {
    uint8_t byte = ((uint8_t*)buf)[i];
    crc = crc ^ byte;
    for (int j = 0; j < 8; j++, byte >>= 1) {
      crc = (crc >> 1) ^ ((crc & 1) ? polynomial : 0);
    }
  }
  return ~crc;
}

// Helper function used to return the lowest value integer given two integers
static uint16_t min(uint16_t a, uint16_t b) { return (a < b) ? a : b; }

// Executes a command on the provisioning log host command (0x3E40)
static libhoth_error exec_provisioning_log_cmd(struct libhoth_device* dev,
                                               const void* req_payload,
                                               size_t req_payload_size,
                                               void* resp_buf,
                                               size_t resp_buf_size,
                                               size_t* out_resp_size) {
  return libhoth_hostcmd_exec_v2(
      dev, /*command=*/HOTH_BASE_CMD(HOTH_PRV_CMD_HOTH_PROVISIONING_LOG),
      /*version=*/0, req_payload, req_payload_size, resp_buf, resp_buf_size,
      out_resp_size);
}

// Runs the command to read a portion of the provisioning log
static int read_chunk_from_provisioning_log(struct libhoth_device* dev,
                                            const void* req_payload,
                                            size_t req_payload_size,
                                            void* resp_buf,
                                            size_t resp_buf_size,
                                            size_t* out_resp_size) {
  return libhoth_hostcmd_exec(
      dev, /*command=*/HOTH_BASE_CMD(HOTH_PRV_CMD_HOTH_PROVISIONING_LOG),
      /*version=*/0, req_payload, req_payload_size, resp_buf, resp_buf_size,
      out_resp_size);
}

int htool_get_provisioning_log(const struct htool_invocation* inv) {
  int status = -1;
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    fprintf(stderr, "Unable to retrieve libhoth_device\n");
    return -1;
  }

  const char* output_file;
  int result = htool_get_param_string(inv, "output", &output_file);
  if (result != 0) {
    return result;
  }

  FILE* output_ptr = NULL;
  output_ptr = fopen(output_file, "wb");
  if (output_ptr == NULL) {
    fprintf(stderr, "Error: %s, when attempting to open file: %s\n",
            strerror(errno), output_file);
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
        // Execute libhoth command to read provisiong log
        int exec_status = read_chunk_from_provisioning_log(
            dev, &request, sizeof(request), &prov_log_hdr_resp,
            sizeof(prov_log_hdr_resp), &response_size);
        if (exec_status != 0) {
          status = exec_status;
          goto cleanup;
        }

        // Get Provisioning Log
        uint16_t bytes_read = 0;
        // Holds the provisioning log data while all of the chunks are being
        // collected
        uint8_t provisioning_log_data[PROVISIONING_LOG_MAX_SIZE];
        while (bytes_read < prov_log_hdr_resp.size) {
          // Read the provisioning log in chunks
          struct hoth_provisioning_log response;
          memset(&response, 0, sizeof(response));
          // Get the size of the data to be requested
          uint16_t chunk_size = min(prov_log_hdr_resp.size - bytes_read,
                                    PROVISIONING_LOG_CHUNK_MAX_SIZE);
          // Update the request to the appropriate size
          request.offset = bytes_read;
          request.size = chunk_size;
          response_size = 0;

          // Execute libhoth command to read provisioning log
          exec_status = read_chunk_from_provisioning_log(
              dev, &request, sizeof(request), &response, sizeof(response),
              &response_size);
          if (exec_status != 0) {
            fprintf(
                stderr,
                "Unexpected Error: Returned status %d,  while trying to send "
                "command to "
                "read the provisioning_log\n",
                exec_status);
            status = exec_status;
            goto cleanup;
          }
          // Check if read bytes matches chunk size
          if (response_size != chunk_size + sizeof(prov_log_hdr_resp)) {
            fprintf(stderr,
                    "Unexpected host command response size. Expecting %lu; Got "
                    "%lu\n",
                    chunk_size + sizeof(prov_log_hdr_resp), response_size);
            status = 1;
            goto cleanup;
          }

          if (bytes_read + chunk_size > PROVISIONING_LOG_MAX_SIZE) {
            fprintf(stderr,
                    "Unexpected Error: Bytes returned: %hu > "
                    "PROVISIONING_LOG_MAX_SIZE: %u\n",
                    bytes_read + chunk_size, PROVISIONING_LOG_MAX_SIZE);
            goto cleanup;
          }

          // Copy the read bytes into the provisioning_log_data buffer
          memcpy(provisioning_log_data + bytes_read, response.data, chunk_size);
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
      fprintf(stderr, "SECURITY_V3 is not supported yet\n");
      goto cleanup;
  }

  // Return success if no other errors have occured at this point
  status = 0;  // Success

cleanup:
  if (output_ptr) {
    fclose(output_ptr);
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
    fprintf(stderr, "Unable to retrieve libhoth_device\n");
    return -1;
  }

  const char* perso_blob_file;
  int result = htool_get_param_string(inv, "perso_blob", &perso_blob_file);
  if (result != 0) {
    return result;
  }

  perso_blob_ptr = fopen(perso_blob_file, "rb");
  if (perso_blob_ptr == NULL) {
    fprintf(stderr, "Error: %s, when attempting to open file: %s\n",
            strerror(errno), perso_blob_file);
    goto cleanup;
  }

  fseek(perso_blob_ptr, 0, SEEK_END);
  uint32_t perso_blob_size = ftell(perso_blob_ptr);
  rewind(perso_blob_ptr);

  perso_blob_data = (uint8_t*)malloc(perso_blob_size);
  size_t bytes_read =
      fread(perso_blob_data, sizeof(uint8_t), perso_blob_size, perso_blob_ptr);
  if (bytes_read <= 0) {
    fprintf(stderr, "Error: %s, when trying to read perso_blob: %s\n",
            strerror(errno), perso_blob_file);
    goto cleanup;
  }

  const char* output_file;
  result = htool_get_param_string(inv, "output", &output_file);
  if (result != 0) {
    status = result;
    goto cleanup;
  }

  if (strlen(output_file) > 0) {
    output_ptr = fopen(output_file, "wb");
    if (output_ptr == NULL) {
      fprintf(stderr, "Error: %s, when attempting to open file: %s\n",
              strerror(errno), output_file);
      goto cleanup;
    }
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
          fprintf(stderr,
                  "Unexpected Error: Returned status %d,  while trying to send "
                  "command to "
                  "read the provisioning_log\n",
                  exec_status);

          status = exec_status;
          goto cleanup;
        }

        if (response_size > PROVISIONING_CERT_MAX_SIZE) {
          fprintf(stderr,
                  "Unexpected Error: Bytes returned: %lu > "
                  "PROVISIONING_CERT_MAX_SIZE: %u\n",
                  response_size, PROVISIONING_CERT_MAX_SIZE);
          goto cleanup;
        }

        // Write the signed provisioning_log into the output file
        if (output_ptr != NULL) {
          fwrite(response, response_size, sizeof(uint8_t), output_ptr);
        }
        break;
      }
    }
    // SECURITY_V3 not supported yet.
    default:
      status = -1;
      fprintf(stderr, "SECURITY_V3 is not supported yet.\n");
      goto cleanup;
  }

  // Return success if no other errors have occured at this point
  status = 0;  // Success

cleanup:
  if (output_ptr) {
    fclose(output_ptr);
  }
  if (perso_blob_ptr) {
    fclose(perso_blob_ptr);
  }
  if (perso_blob_data) {
    free(perso_blob_data);
  }
  return status;
}

// Helper to read a binary file with size validation.
static int read_binary_file(const char* path, uint8_t* buf, size_t min_size,
                            size_t max_size, size_t* out_size) {
  FILE* file = fopen(path, "rb");
  if (file == NULL) {
    fprintf(stderr, "Error: %s, when attempting to open file: %s\n",
            strerror(errno), path);
    return -1;
  }

  const size_t read_bytes = fread(buf, 1, max_size, file);
  // A full buffer may mean the file was truncated; check for trailing bytes.
  const bool too_large = (read_bytes == max_size) && (fgetc(file) != EOF);
  const bool read_error = ferror(file) != 0;
  fclose(file);

  if (read_error) {
    fprintf(stderr, "Error reading %s\n", path);
    return -1;
  }
  if (too_large) {
    if (min_size == max_size) {
      fprintf(stderr,
              "Error: %s exceeds %zu bytes (must be exactly %zu bytes)\n", path,
              max_size, max_size);
    } else {
      fprintf(stderr, "Error: %s exceeds maximum size of %zu bytes\n", path,
              max_size);
    }
    return -1;
  }
  if (read_bytes < min_size) {
    if (min_size == max_size) {
      fprintf(stderr, "Error: %s size (%zu) must be exactly %zu bytes\n", path,
              read_bytes, min_size);
    } else if (read_bytes == 0) {
      fprintf(stderr, "Error: %s is empty\n", path);
    } else {
      fprintf(stderr, "Error: %s size (%zu) is less than minimum %zu bytes\n",
              path, read_bytes, min_size);
    }
    return -1;
  }

  if (out_size != NULL) {
    *out_size = read_bytes;
  }
  return 0;
}

// Reads the encrypted secrets from `--secrets` (a binary file, as
// produced by the offline encryption tools).
static int get_secrets(const struct htool_invocation* inv, uint8_t* secrets,
                       size_t secrets_capacity, size_t* secrets_size) {
  const char* secrets_file;
  if (htool_get_param_string(inv, "secrets", &secrets_file) != 0 ||
      strlen(secrets_file) == 0) {
    fprintf(stderr, "--secrets must be specified.\n");
    return -1;
  }

  return read_binary_file(secrets_file, secrets, 1, secrets_capacity,
                          secrets_size);
}

int htool_provisioning_store_secrets(const struct htool_invocation* inv) {
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  uint8_t secrets[HOTH_KEY_PROVISIONING_MAX_SECRETS_SIZE];
  size_t secrets_size = 0;
  if (get_secrets(inv, secrets, sizeof(secrets), &secrets_size) != 0) {
    return -1;
  }

  const size_t request_size =
      sizeof(struct hoth_key_provisioning_request_header) + secrets_size;

  struct hoth_key_provisioning_store_secrets_request req = {
      .hdr =
          {
              .version = HOTH_KEY_PROVISIONING_REQUEST_VERSION,
              .command = HOTH_KEY_PROVISIONING_STORE_SECRETS,
              .size = (uint16_t)request_size,
          },
  };
  memcpy(req.secrets, secrets, secrets_size);

  size_t response_size = 0;
  libhoth_error err = libhoth_hostcmd_exec_v2(
      dev, HOTH_BASE_CMD(HOTH_PRV_CMD_HOTH_KEY_PROVISIONING),
      /*version=*/0, &req, request_size, NULL, 0, &response_size);
  if (err != HOTH_SUCCESS) {
    fprintf(stderr,
            "Error: 'key_provisioning_store_secrets' failed (0x%016" PRIx64
            "): ",
            err);
    libhoth_log_err(stderr, err);
    return -1;
  }
  printf("Stored %zu bytes of encrypted secrets\n", secrets_size);
  return 0;
}

int htool_provisioning_write(const struct htool_invocation* inv) {
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    fprintf(stderr, "Unable to retrieve libhoth_device\n");
    return -1;
  }

  const char* input_file;
  if (htool_get_param_string(inv, "input", &input_file) != 0 ||
      strlen(input_file) == 0) {
    fprintf(stderr, "--input must be specified.\n");
    return -1;
  }

  uint8_t log_data[PROVISIONING_LOG_MAX_SIZE];
  size_t file_size = 0;
  if (read_binary_file(input_file, log_data, 1, PROVISIONING_LOG_MAX_SIZE,
                       &file_size) != 0) {
    return -1;
  }

  uint16_t bytes_written = 0;
  while (bytes_written < file_size) {
    uint16_t chunk_size = (uint16_t)(file_size - bytes_written);
    if (chunk_size > PROVISIONING_LOG_WRITE_CHUNK_MAX_SIZE) {
      chunk_size = PROVISIONING_LOG_WRITE_CHUNK_MAX_SIZE;
    }

    struct hoth_provisioning_log_write_request write_req = {
        .req =
            {
                .version = 1,
                .operation = PROVISIONING_LOG_WRITE,
                .reserved = 0,
                .offset = bytes_written,
                .size = chunk_size,
                .checksum = 0,
            },
    };
    memcpy(write_req.data, log_data + bytes_written, chunk_size);

    size_t response_size = 0;
    libhoth_error err = exec_provisioning_log_cmd(
        dev, &write_req, sizeof(write_req.req) + chunk_size, NULL, 0,
        &response_size);
    if (err != HOTH_SUCCESS) {
      fprintf(
          stderr,
          "Error: 'provisioning_log_write' failed (0x%016" PRIx64 "): ", err);
      libhoth_log_err(stderr, err);
      return -1;
    }
    bytes_written += chunk_size;
  }

  struct hoth_provisioning_log_request commit_req = {
      .version = 1,
      .operation = PROVISIONING_LOG_COMMIT,
      .reserved = 0,
      .offset = 0,
      .size = (uint16_t)file_size,
      .checksum = crc32(0, log_data, file_size),
  };
  size_t response_size = 0;
  libhoth_error err = exec_provisioning_log_cmd(
      dev, &commit_req, sizeof(commit_req), NULL, 0, &response_size);
  if (err != HOTH_SUCCESS) {
    fprintf(
        stderr,
        "Error: 'provisioning_log_commit' failed (0x%016" PRIx64 "): ", err);
    libhoth_log_err(stderr, err);
    return -1;
  }

  printf("Successfully wrote and committed %zu bytes of provisioning log\n",
         file_size);
  return 0;
}

int htool_provisioning_load_mldsa_key(const struct htool_invocation* inv) {
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    fprintf(stderr, "Unable to retrieve libhoth_device\n");
    return -1;
  }

  const char* key_file;
  if (htool_get_param_string(inv, "key", &key_file) != 0 ||
      strlen(key_file) == 0) {
    fprintf(stderr, "--key must be specified.\n");
    return -1;
  }

  uint8_t key_buf[HOTH_KEY_PROVISIONING_MLDSA44_PUBLIC_KEY_BYTES];
  if (read_binary_file(key_file, key_buf, sizeof(key_buf), sizeof(key_buf),
                       NULL) != 0) {
    return -1;
  }

  uint16_t offset = 0;
  while (offset < sizeof(key_buf)) {
    uint16_t chunk_size = (uint16_t)(sizeof(key_buf) - offset);
    if (chunk_size > HOTH_KEY_PROVISIONING_LOAD_KEY_CHUNK_MAX_SIZE) {
      chunk_size = HOTH_KEY_PROVISIONING_LOAD_KEY_CHUNK_MAX_SIZE;
    }

    const size_t req_size =
        sizeof(struct hoth_key_provisioning_request_header) +
        sizeof(struct hoth_key_provisioning_load_key_args) + chunk_size;

    struct hoth_key_provisioning_load_key_request req = {
        .hdr =
            {
                .version = HOTH_KEY_PROVISIONING_REQUEST_VERSION,
                .command = HOTH_KEY_PROVISIONING_LOAD_MLDSA_PUBLIC_KEY,
                .size = (uint16_t)req_size,
            },
        .args =
            {
                .offset = offset,
                .size = chunk_size,
            },
    };
    memcpy(req.data, key_buf + offset, chunk_size);

    size_t response_size = 0;
    libhoth_error err = libhoth_hostcmd_exec_v2(
        dev, HOTH_BASE_CMD(HOTH_PRV_CMD_HOTH_KEY_PROVISIONING),
        /*version=*/0, &req, req_size, NULL, 0, &response_size);
    if (err != HOTH_SUCCESS) {
      fprintf(stderr,
              "Error: 'key_provisioning_load_mldsa_key' failed (0x%016" PRIx64
              "): ",
              err);
      libhoth_log_err(stderr, err);
      return -1;
    }

    offset += chunk_size;
  }

  printf("ML-DSA public key loaded successfully\n");
  return 0;
}
