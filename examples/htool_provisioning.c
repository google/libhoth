#include "htool_provisioning.h"

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "htool.h"
#include "htool_cmd.h"
#include "htool_security_version.h"
#include "protocol/provisioning.h"
#include "transports/libhoth_device.h"

int htool_get_provisioning_log(const struct htool_invocation* inv) {
  int status = -1;
  FILE* output_ptr = NULL;
  uint8_t provisioning_log_data[PROVISIONING_LOG_MAX_SIZE];
  size_t bytes_read = 0;

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

  output_ptr = fopen(output_file, "wb");
  if (output_ptr == NULL) {
    fprintf(stderr, "Error: %s, when attempting to open file: %s\n",
            strerror(errno), output_file);
    goto cleanup;
  }

  // SECURITY_V3 not supported yet.
  if (htool_get_security_version(dev) != LIBHOTH_SECURITY_V2) {
    status = -1;
    fprintf(stderr, "SECURITY_V3 is not supported yet\n");
    goto cleanup;
  }

  status = libhoth_provisioning_log_read(
      dev, provisioning_log_data, sizeof(provisioning_log_data), &bytes_read);
  if (status != 0) {
    goto cleanup;
  }

  // Write the provisioning_log that was read into the output file
  fwrite(provisioning_log_data, bytes_read, sizeof(uint8_t), output_ptr);

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
  uint8_t cert[PROVISIONING_CERT_MAX_SIZE];
  size_t cert_size = 0;

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

  // SECURITY_V3 not supported yet.
  if (htool_get_security_version(dev) != LIBHOTH_SECURITY_V2) {
    status = -1;
    fprintf(stderr, "SECURITY_V3 is not supported yet.\n");
    goto cleanup;
  }

  memset(cert, 0, sizeof(cert));
  status = libhoth_provisioning_log_validate_and_sign(
      dev, perso_blob_data, perso_blob_size, cert, sizeof(cert), &cert_size);
  if (status != 0) {
    goto cleanup;
  }

  // Write the signed provisioning_log into the output file
  if (output_ptr != NULL) {
    fwrite(cert, cert_size, sizeof(uint8_t), output_ptr);
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

  libhoth_error err =
      libhoth_key_provisioning_store_secrets(dev, secrets, secrets_size);
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

  libhoth_error err = libhoth_provisioning_log_write(dev, log_data, file_size);
  if (err != HOTH_SUCCESS) {
    fprintf(stderr,
            "Error: 'provisioning_log_write' failed (0x%016" PRIx64 "): ", err);
    libhoth_log_err(stderr, err);
    return -1;
  }

  err = libhoth_provisioning_log_commit(dev, log_data, file_size);
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

  libhoth_error err =
      libhoth_key_provisioning_load_mldsa_key(dev, key_buf, sizeof(key_buf));
  if (err != HOTH_SUCCESS) {
    fprintf(stderr,
            "Error: 'key_provisioning_load_mldsa_key' failed (0x%016" PRIx64
            "): ",
            err);
    libhoth_log_err(stderr, err);
    return -1;
  }

  printf("ML-DSA public key loaded successfully\n");
  return 0;
}
