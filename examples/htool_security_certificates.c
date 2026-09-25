#include "htool_security_certificates.h"

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "host_commands.h"
#include "htool.h"
#include "htool_cmd.h"
#include "htool_macros.h"
#include "htool_security_v2.h"
#include "htool_security_version.h"
#include "protocol/host_cmd.h"

static int get_cert_v2_data(const struct htool_invocation* inv,
                            uint32_t major_command, uint32_t minor_command,
                            uint8_t* cert, uint32_t cert_size,
                            uint8_t response_storage_hdr[],
                            uint32_t response_storage_hdr_size) {
  int status = -1;
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  const char* output_file;
  if (htool_get_param_string(inv, "output", &output_file) != 0) {
    return -1;
  }

  FILE* output_ptr = NULL;
  output_ptr = fopen(output_file, "wb");
  if (output_ptr == NULL) {
    fprintf(stderr, "Error: %s, when attempting to open file: %s\n",
            strerror(errno), output_file);
    goto cleanup;
  }

  libhoth_security_version sv = htool_get_security_version(dev);
  switch (sv) {
    case LIBHOTH_SECURITY_V2: {
      // Send Get Attestation Public Certificate Request
      uint8_t request_storage_hdr[HOTH_SECURITY_V2_REQUEST_SIZE(0)] = {};

      struct security_v2_param response_params[] = {
          {
              .data = cert,
              .size = cert_size,
          },
      };
      int hoth_status = htool_exec_security_v2_cmd(
          dev, /*major=*/
          major_command,
          /*minor=*/
          minor_command,
          /*base_command=*/HOTH_BASE_CMD(HOTH_PRV_CMD_HOTH_SECURITY_V2),
          SECURITY_V2_BUFFER_PARAM(request_storage_hdr), NULL, 0,
          SECURITY_V2_BUFFER_PARAM_WITH_VARIABLE_SIZE(
              response_storage_hdr, response_storage_hdr_size),
          response_params, ARRAY_SIZE(response_params));
      if (hoth_status != 0) {
        fprintf(stderr,
                "Unexpected Error: Returned status %d, while trying to send "
                "command to get the Certificate\n",
                hoth_status);
        status = hoth_status;
        goto cleanup;
      }
      // Write the certificate that was read into the output file
      fwrite(cert, cert_size, NUM_OF_CERTS_WRITTEN, output_ptr);
      break;
    }
    // SECURITY_V3 not supported yet.
    default:
      fprintf(stderr, "SECURITY_V3 not supported yet\n");
      goto cleanup;
  }
  status = 0;
cleanup:
  if (output_ptr) {
    fclose(output_ptr);
  }
  return status;
}

int htool_get_attestation_pub_cert(const struct htool_invocation* inv) {
  uint8_t cert[ATTESTATION_CERT_SIZE] = {0};
  uint8_t response_storage_hdr[HOTH_SECURITY_V2_RESPONSE_SIZE(1) +
                               ATTESTATION_CERT_SIZE] = {};
  return get_cert_v2_data(
      inv, HOTH_PRV_CMD_HOTH_SECURITY_V2_GET_CERTIFICATES_MAJOR_COMMAND,
      HOTH_PRV_CMD_HOTH_SECURITY_V2_GET_ATTESTATION_PUB_CERT_MINOR_COMMAND,
      cert, ATTESTATION_CERT_SIZE, response_storage_hdr,
      sizeof(response_storage_hdr));
}

int htool_get_signed_attestation_pub_cert(const struct htool_invocation* inv) {
  uint8_t cert[ATTESTATION_CERT_SIZE] = {0};
  uint8_t response_storage_hdr[HOTH_SECURITY_V2_RESPONSE_SIZE(1) +
                               ATTESTATION_CERT_SIZE] = {};
  return get_cert_v2_data(
      inv, HOTH_PRV_CMD_HOTH_SECURITY_V2_GET_CERTIFICATES_MAJOR_COMMAND,
      HOTH_PRV_CMD_HOTH_SECURITY_V2_GET_SIGNED_ATTESTATION_PUB_CERT_MINOR_COMMAND,
      cert, ATTESTATION_CERT_SIZE, response_storage_hdr,
      sizeof(response_storage_hdr));
}

int htool_get_alias_key_v0_cert(const struct htool_invocation* inv) {
  uint8_t cert[ALIAS_KEY_V0_SIZE] = {0};
  uint8_t response_storage_hdr[HOTH_SECURITY_V2_RESPONSE_SIZE(1) +
                               ALIAS_KEY_V0_SIZE] = {};
  return get_cert_v2_data(
      inv, HOTH_PRV_CMD_HOTH_SECURITY_V2_GET_CERTIFICATES_MAJOR_COMMAND,
      HOTH_PRV_CMD_HOTH_SECURITY_V2_GET_ALIAS_KEY_MINOR_COMMAND, cert,
      ALIAS_KEY_V0_SIZE, response_storage_hdr, sizeof(response_storage_hdr));
}

int htool_get_alias_key_v1_cert(const struct htool_invocation* inv) {
  uint8_t cert[ALIAS_KEY_V1_SIZE] = {0};
  uint8_t response_storage_hdr[HOTH_SECURITY_V2_RESPONSE_SIZE(1) +
                               ALIAS_KEY_V1_SIZE] = {};
  return get_cert_v2_data(
      inv, HOTH_PRV_CMD_HOTH_SECURITY_V2_GET_CERTIFICATES_MAJOR_COMMAND,
      HOTH_PRV_CMD_HOTH_SECURITY_V2_GET_ALIAS_KEY_MINOR_COMMAND, cert,
      ALIAS_KEY_V1_SIZE, response_storage_hdr, sizeof(response_storage_hdr));
}

int htool_get_alias_key_cert(const struct htool_invocation* inv) {
  int status = -1;
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  uint32_t version;
  if (htool_get_param_u32(inv, "version", &version) != 0) {
    return -1;
  }
  switch (version) {
    case 0:
      status = htool_get_alias_key_v0_cert(inv);
      break;
    case 1:
      status = htool_get_alias_key_v1_cert(inv);
      break;
    default:
      fprintf(stderr, "Unknown Alias Key Version received: %d\n", version);
      break;
  }

  return status;
}

int htool_get_device_id_cert(const struct htool_invocation* inv) {
  int status = -1;
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  // A user can supply only a cert_output field in order to return only the
  // Device ID Certificate, only an endorsement_cert_output field in order to
  // only return the Endorsement Device ID Certificate, or both to return both
  // certificates.
  bool is_cert_output_file_provided = false;
  bool is_endorsement_cert_output_file_provided = false;

  const char* cert_output_file;
  if (htool_get_param_string(inv, "cert_output", &cert_output_file) != 0) {
    return -1;
  }

  FILE* cert_output_ptr = NULL;
  FILE* endorsement_cert_output_ptr = NULL;

  // The default value for cert_output is an empty string
  // so if the flag is not present the value will default to an empty string
  if (strlen(cert_output_file) > 0) {
    cert_output_ptr = fopen(cert_output_file, "wb");
    if (cert_output_ptr == NULL) {
      fprintf(stderr, "Error: %s, when attempting to open file: %s\n",
              strerror(errno), cert_output_file);
      goto cleanup;
    }
    is_cert_output_file_provided = true;
  }

  const char* endorsement_cert_output_file;
  if (htool_get_param_string(inv, "endorsement_cert_output",
                             &endorsement_cert_output_file) != 0) {
    goto cleanup;
  }

  // The default value for endorsement_cert_output is an empty string
  // so if the flag is not present the value will default to an empty string
  if (strlen(endorsement_cert_output_file) > 0) {
    endorsement_cert_output_ptr = fopen(endorsement_cert_output_file, "wb");
    if (endorsement_cert_output_ptr == NULL) {
      fprintf(stderr, "Error: %s, when attempting to open file: %s.\n",
              strerror(errno), endorsement_cert_output_file);
      goto cleanup;
    }
    is_endorsement_cert_output_file_provided = true;
  }

  if (!is_cert_output_file_provided &&
      !is_endorsement_cert_output_file_provided) {
    fprintf(
        stderr,
        "Error: No valid cert_output provided and No valid "
        "endorsement_cert_output provided."
        " Only a cert_output field can be provided to return only the Device "
        "ID Certificate,"
        " only an endorsement_cert_output field can be provided in order to "
        "only return the Endorsement Device ID Certificate,"
        " or both can be provided to return both certificates.\n");
    goto cleanup;
  }

  uint8_t certificate[DEVICE_CERT_SIZE] = {0};
  uint8_t endorsement_certificate[DEVICE_ENDORSEMENT_CERT_SIZE] = {0};
  libhoth_security_version sv = htool_get_security_version(dev);
  switch (sv) {
    case LIBHOTH_SECURITY_V2: {
      // Send Get Device ID Certificates Request
      uint8_t request_storage_hdr[HOTH_SECURITY_V2_REQUEST_SIZE(0)] = {};
      uint8_t response_storage_hdr[HOTH_SECURITY_V2_RESPONSE_SIZE(2) +
                                   sizeof(certificate) +
                                   sizeof(endorsement_certificate)] = {};

      struct security_v2_param response_params[] = {
          {
              .data = &certificate,
              .size = sizeof(certificate),
          },
          {
              .data = &endorsement_certificate,
              .size = sizeof(endorsement_certificate),
          },

      };
      // This single command returns both the device_id_certificate and the
      // device_id_endorsement_certificate
      int hoth_status = htool_exec_security_v2_cmd(
          dev, /*major=*/
          HOTH_PRV_CMD_HOTH_SECURITY_V2_GET_CERTIFICATES_MAJOR_COMMAND,
          /*minor=*/HOTH_PRV_CMD_HOTH_SECURITY_V2_GET_DEVICE_ID_MINOR_COMMAND,
          /*base_command=*/HOTH_BASE_CMD(HOTH_PRV_CMD_HOTH_SECURITY_V2),
          SECURITY_V2_BUFFER_PARAM(request_storage_hdr), NULL, 0,
          SECURITY_V2_BUFFER_PARAM(response_storage_hdr), response_params,
          ARRAY_SIZE(response_params));
      if (hoth_status != 0) {
        fprintf(stderr,
                "Unexpected Error: Returned status %d, while trying to send "
                "command to get the Device ID Certificates\n",
                hoth_status);
        status = hoth_status;
        goto cleanup;
      }
      // Write the certificates that were read into the output files
      if (is_cert_output_file_provided) {
        fwrite(&certificate, sizeof(certificate), NUM_OF_CERTS_WRITTEN,
               cert_output_ptr);
      }
      if (is_endorsement_cert_output_file_provided) {
        fwrite(&endorsement_certificate, sizeof(endorsement_certificate),
               NUM_OF_CERTS_WRITTEN, endorsement_cert_output_ptr);
      }
      break;
    }
    // SECURITY_V3 not supported yet.
    default:
      fprintf(stderr, "SECURITY_V3 not supported yet\n");
      goto cleanup;
  }
  status = 0;
cleanup:
  if (cert_output_ptr) {
    fclose(cert_output_ptr);
  }
  if (endorsement_cert_output_ptr) {
    fclose(endorsement_cert_output_ptr);
  }
  return status;
}

// SecurityV2 parameters are padded to 4-byte alignment on the wire. Ensure all
// fixed-size attestation key buffer sizes are multiples of 4 so buffer sizing
// macros remain exact.
_Static_assert(ATTESTATION_KEY_CSR_V1_SIZE % 4 == 0,
               "ATTESTATION_KEY_CSR_V1_SIZE must be 4-byte aligned");
_Static_assert(ATTESTATION_KEY_CSR_V2_SIZE % 4 == 0,
               "ATTESTATION_KEY_CSR_V2_SIZE must be 4-byte aligned");
_Static_assert(WRAPPED_ATTESTATION_KEY_SIZE % 4 == 0,
               "WRAPPED_ATTESTATION_KEY_SIZE must be 4-byte aligned");
_Static_assert(ATTESTATION_CERT_SIZE % 4 == 0,
               "ATTESTATION_CERT_SIZE must be 4-byte aligned");

static int read_exact_file(const char* filename, uint8_t* buf, size_t size) {
  FILE* fp = fopen(filename, "rb");
  if (fp == NULL) {
    fprintf(stderr, "Error: %s, when attempting to open file: %s\n",
            strerror(errno), filename);
    return -1;
  }
  size_t bytes_read = fread(buf, 1, size, fp);
  int extra = fgetc(fp);
  int stream_err = ferror(fp);
  fclose(fp);
  if (bytes_read != size || extra != EOF || stream_err != 0) {
    fprintf(stderr, "Error: File %s must be exactly %zu bytes\n", filename,
            size);
    return -1;
  }
  return 0;
}

static int write_exact_file(const char* filename, const uint8_t* buf,
                            size_t size) {
  FILE* fp = fopen(filename, "wb");
  if (fp == NULL) {
    fprintf(stderr, "Error: %s, when attempting to open file: %s\n",
            strerror(errno), filename);
    return -1;
  }
  size_t bytes_written = fwrite(buf, 1, size, fp);
  int stream_err = ferror(fp);
  fclose(fp);
  if (bytes_written != size || stream_err != 0) {
    fprintf(stderr, "Error: Failed to write %zu bytes to %s\n", size, filename);
    return -1;
  }
  return 0;
}

static int exec_unload_attestation_key(struct libhoth_device* dev) {
  uint8_t request_storage_hdr[HOTH_SECURITY_V2_REQUEST_SIZE(0)] = {};
  uint8_t response_storage_hdr[HOTH_SECURITY_V2_RESPONSE_SIZE(0)] = {};

  int hoth_status = htool_exec_security_v2_cmd(
      dev,
      /*major=*/HOTH_PRV_CMD_HOTH_SECURITY_V2_GET_CERTIFICATES_MAJOR_COMMAND,
      /*minor=*/
      HOTH_PRV_CMD_HOTH_SECURITY_V2_UNLOAD_ATTESTATION_KEY_MINOR_COMMAND,
      /*base_command=*/HOTH_BASE_CMD(HOTH_PRV_CMD_HOTH_SECURITY_V2),
      SECURITY_V2_BUFFER_PARAM(request_storage_hdr), NULL, 0,
      SECURITY_V2_BUFFER_PARAM(response_storage_hdr), NULL, 0);
  if (hoth_status != 0) {
    fprintf(
        stderr,
        "Unexpected Error: Returned status %d, while trying to send command to "
        "unload the Attestation Key\n",
        hoth_status);
  }
  return hoth_status;
}

static int exec_gen_attestation_key_v1(
    struct libhoth_device* dev, uint8_t csr[ATTESTATION_KEY_CSR_V1_SIZE],
    uint8_t wrapped_key[WRAPPED_ATTESTATION_KEY_SIZE]) {
  uint8_t request_storage_hdr[HOTH_SECURITY_V2_REQUEST_SIZE(0)] = {};
  uint8_t response_storage_hdr[HOTH_SECURITY_V2_RESPONSE_SIZE(2) +
                               ATTESTATION_KEY_CSR_V1_SIZE +
                               WRAPPED_ATTESTATION_KEY_SIZE] = {};
  struct security_v2_param response_params[] = {
      {
          .data = csr,
          .size = ATTESTATION_KEY_CSR_V1_SIZE,
      },
      {
          .data = wrapped_key,
          .size = WRAPPED_ATTESTATION_KEY_SIZE,
      },
  };
  int hoth_status = htool_exec_security_v2_cmd(
      dev,
      /*major=*/HOTH_PRV_CMD_HOTH_SECURITY_V2_GET_CERTIFICATES_MAJOR_COMMAND,
      /*minor=*/
      HOTH_PRV_CMD_HOTH_SECURITY_V2_GEN_ATTESTATION_KEY_USING_CSR_V1_MINOR_COMMAND,
      /*base_command=*/HOTH_BASE_CMD(HOTH_PRV_CMD_HOTH_SECURITY_V2),
      SECURITY_V2_BUFFER_PARAM(request_storage_hdr), NULL, 0,
      SECURITY_V2_BUFFER_PARAM(response_storage_hdr), response_params,
      ARRAY_SIZE(response_params));
  if (hoth_status != 0) {
    fprintf(
        stderr,
        "Unexpected Error: Returned status %d, while trying to send command to "
        "generate the Attestation Key\n",
        hoth_status);
  }
  return hoth_status;
}

static int exec_gen_attestation_key_v2(
    struct libhoth_device* dev, uint32_t fw_major_version,
    uint8_t csr[ATTESTATION_KEY_CSR_V2_SIZE],
    uint8_t wrapped_key[WRAPPED_ATTESTATION_KEY_SIZE]) {
  uint32_t csr_version = 2;
  struct security_v2_param request_params[] = {
      {
          .data = &csr_version,
          .size = sizeof(csr_version),
      },
      {
          .data = &fw_major_version,
          .size = sizeof(fw_major_version),
      },
  };
  uint8_t request_storage_hdr[HOTH_SECURITY_V2_REQUEST_SIZE(2) +
                              sizeof(csr_version) + sizeof(fw_major_version)] =
      {};
  uint8_t response_storage_hdr[HOTH_SECURITY_V2_RESPONSE_SIZE(2) +
                               ATTESTATION_KEY_CSR_V2_SIZE +
                               WRAPPED_ATTESTATION_KEY_SIZE] = {};
  struct security_v2_param response_params[] = {
      {
          .data = csr,
          .size = ATTESTATION_KEY_CSR_V2_SIZE,
      },
      {
          .data = wrapped_key,
          .size = WRAPPED_ATTESTATION_KEY_SIZE,
      },
  };
  int hoth_status = htool_exec_security_v2_cmd(
      dev,
      /*major=*/HOTH_PRV_CMD_HOTH_SECURITY_V2_GET_CERTIFICATES_MAJOR_COMMAND,
      /*minor=*/
      HOTH_PRV_CMD_HOTH_SECURITY_V2_GEN_VERSIONED_ATTESTATION_KEY_MINOR_COMMAND,
      /*base_command=*/HOTH_BASE_CMD(HOTH_PRV_CMD_HOTH_SECURITY_V2),
      SECURITY_V2_BUFFER_PARAM(request_storage_hdr), request_params,
      ARRAY_SIZE(request_params),
      SECURITY_V2_BUFFER_PARAM(response_storage_hdr), response_params,
      ARRAY_SIZE(response_params));
  if (hoth_status != 0) {
    fprintf(
        stderr,
        "Unexpected Error: Returned status %d, while trying to send command to "
        "generate the Attestation Key\n",
        hoth_status);
  }
  return hoth_status;
}

static int exec_load_attestation_key(
    struct libhoth_device* dev,
    uint8_t wrapped_key[WRAPPED_ATTESTATION_KEY_SIZE],
    uint8_t cert[ATTESTATION_CERT_SIZE]) {
  uint8_t request_storage_hdr[HOTH_SECURITY_V2_REQUEST_SIZE(2) +
                              WRAPPED_ATTESTATION_KEY_SIZE +
                              ATTESTATION_CERT_SIZE] = {};
  uint8_t response_storage_hdr[HOTH_SECURITY_V2_RESPONSE_SIZE(0)] = {};
  struct security_v2_param request_params[] = {
      {
          .data = wrapped_key,
          .size = WRAPPED_ATTESTATION_KEY_SIZE,
      },
      {
          .data = cert,
          .size = ATTESTATION_CERT_SIZE,
      },
  };
  int hoth_status = htool_exec_security_v2_cmd(
      dev,
      /*major=*/HOTH_PRV_CMD_HOTH_SECURITY_V2_GET_CERTIFICATES_MAJOR_COMMAND,
      /*minor=*/
      HOTH_PRV_CMD_HOTH_SECURITY_V2_LOAD_ATTESTATION_KEY_MINOR_COMMAND,
      /*base_command=*/HOTH_BASE_CMD(HOTH_PRV_CMD_HOTH_SECURITY_V2),
      SECURITY_V2_BUFFER_PARAM(request_storage_hdr), request_params,
      ARRAY_SIZE(request_params),
      SECURITY_V2_BUFFER_PARAM(response_storage_hdr), NULL, 0);
  if (hoth_status != 0) {
    fprintf(
        stderr,
        "Unexpected Error: Returned status %d, while trying to send command to "
        "load the Attestation Key\n",
        hoth_status);
  }
  return hoth_status;
}

static int exec_load_attestation_key_from_csr_v1(
    struct libhoth_device* dev,
    uint8_t wrapped_key[WRAPPED_ATTESTATION_KEY_SIZE],
    uint8_t csr[ATTESTATION_KEY_CSR_V1_SIZE]) {
  uint8_t request_storage_hdr[HOTH_SECURITY_V2_REQUEST_SIZE(2) +
                              WRAPPED_ATTESTATION_KEY_SIZE +
                              ATTESTATION_KEY_CSR_V1_SIZE] = {};
  uint8_t response_storage_hdr[HOTH_SECURITY_V2_RESPONSE_SIZE(0)] = {};
  struct security_v2_param request_params[] = {
      {
          .data = wrapped_key,
          .size = WRAPPED_ATTESTATION_KEY_SIZE,
      },
      {
          .data = csr,
          .size = ATTESTATION_KEY_CSR_V1_SIZE,
      },
  };
  int hoth_status = htool_exec_security_v2_cmd(
      dev,
      /*major=*/HOTH_PRV_CMD_HOTH_SECURITY_V2_GET_CERTIFICATES_MAJOR_COMMAND,
      /*minor=*/
      HOTH_PRV_CMD_HOTH_SECURITY_V2_LOAD_ATTESTATION_KEY_FROM_CSR_V1_MINOR_COMMAND,
      /*base_command=*/HOTH_BASE_CMD(HOTH_PRV_CMD_HOTH_SECURITY_V2),
      SECURITY_V2_BUFFER_PARAM(request_storage_hdr), request_params,
      ARRAY_SIZE(request_params),
      SECURITY_V2_BUFFER_PARAM(response_storage_hdr), NULL, 0);
  if (hoth_status != 0) {
    fprintf(
        stderr,
        "Unexpected Error: Returned status %d, while trying to send command to "
        "load the Attestation Key from CSR\n",
        hoth_status);
  }
  return hoth_status;
}

int htool_unload_attestation_key(const struct htool_invocation* inv) {
  (void)inv;
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  libhoth_security_version sv = htool_get_security_version(dev);
  switch (sv) {
    case LIBHOTH_SECURITY_V2:
      return exec_unload_attestation_key(dev);
    // SECURITY_V3 not supported yet.
    default:
      fprintf(stderr, "SECURITY_V3 not supported yet\n");
      return -1;
  }
}

int htool_gen_attestation_key_v1(const struct htool_invocation* inv) {
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  const char* csr_output_file;
  if (htool_get_param_string(inv, "csr_output", &csr_output_file) != 0) {
    return -1;
  }

  const char* wrapped_key_output_file;
  if (htool_get_param_string(inv, "wrapped_key_output",
                             &wrapped_key_output_file) != 0) {
    return -1;
  }

  bool is_csr_output_provided = strlen(csr_output_file) > 0;
  bool is_wrapped_key_output_provided = strlen(wrapped_key_output_file) > 0;

  if (!is_csr_output_provided && !is_wrapped_key_output_provided) {
    fprintf(
        stderr,
        "Error: No valid csr_output provided and no valid wrapped_key_output "
        "provided.\n");
    return -1;
  }

  uint8_t csr[ATTESTATION_KEY_CSR_V1_SIZE] = {0};
  uint8_t wrapped_key[WRAPPED_ATTESTATION_KEY_SIZE] = {0};
  libhoth_security_version sv = htool_get_security_version(dev);
  switch (sv) {
    case LIBHOTH_SECURITY_V2: {
      int hoth_status = exec_gen_attestation_key_v1(dev, csr, wrapped_key);
      if (hoth_status != 0) {
        return hoth_status;
      }
      if (is_csr_output_provided &&
          write_exact_file(csr_output_file, csr, sizeof(csr)) != 0) {
        return -1;
      }
      if (is_wrapped_key_output_provided &&
          write_exact_file(wrapped_key_output_file, wrapped_key,
                           sizeof(wrapped_key)) != 0) {
        return -1;
      }
      return 0;
    }
    // SECURITY_V3 not supported yet.
    default:
      fprintf(stderr, "SECURITY_V3 not supported yet\n");
      return -1;
  }
}

int htool_gen_attestation_key_v2(const struct htool_invocation* inv) {
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  uint32_t fw_major_version;
  if (htool_get_param_u32(inv, "fw_major_version", &fw_major_version) != 0) {
    return -1;
  }

  const char* csr_output_file;
  if (htool_get_param_string(inv, "csr_output", &csr_output_file) != 0) {
    return -1;
  }

  const char* wrapped_key_output_file;
  if (htool_get_param_string(inv, "wrapped_key_output",
                             &wrapped_key_output_file) != 0) {
    return -1;
  }

  bool is_csr_output_provided = strlen(csr_output_file) > 0;
  bool is_wrapped_key_output_provided = strlen(wrapped_key_output_file) > 0;

  if (!is_csr_output_provided && !is_wrapped_key_output_provided) {
    fprintf(
        stderr,
        "Error: No valid csr_output provided and no valid wrapped_key_output "
        "provided.\n");
    return -1;
  }

  uint8_t csr[ATTESTATION_KEY_CSR_V2_SIZE] = {0};
  uint8_t wrapped_key[WRAPPED_ATTESTATION_KEY_SIZE] = {0};
  libhoth_security_version sv = htool_get_security_version(dev);
  switch (sv) {
    case LIBHOTH_SECURITY_V2: {
      int hoth_status =
          exec_gen_attestation_key_v2(dev, fw_major_version, csr, wrapped_key);
      if (hoth_status != 0) {
        return hoth_status;
      }
      if (is_csr_output_provided &&
          write_exact_file(csr_output_file, csr, sizeof(csr)) != 0) {
        return -1;
      }
      if (is_wrapped_key_output_provided &&
          write_exact_file(wrapped_key_output_file, wrapped_key,
                           sizeof(wrapped_key)) != 0) {
        return -1;
      }
      return 0;
    }
    // SECURITY_V3 not supported yet.
    default:
      fprintf(stderr, "SECURITY_V3 not supported yet\n");
      return -1;
  }
}

int htool_load_attestation_key(const struct htool_invocation* inv) {
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  const char* wrapped_key_file;
  if (htool_get_param_string(inv, "wrapped_key", &wrapped_key_file) != 0) {
    return -1;
  }

  const char* cert_file;
  if (htool_get_param_string(inv, "cert", &cert_file) != 0) {
    return -1;
  }

  if (strlen(wrapped_key_file) == 0 || strlen(cert_file) == 0) {
    fprintf(
        stderr,
        "Error: Both wrapped_key and cert files must be provided to load the "
        "Attestation Key.\n");
    return -1;
  }

  uint8_t wrapped_key[WRAPPED_ATTESTATION_KEY_SIZE] = {0};
  if (read_exact_file(wrapped_key_file, wrapped_key, sizeof(wrapped_key)) !=
      0) {
    return -1;
  }

  uint8_t cert[ATTESTATION_CERT_SIZE] = {0};
  if (read_exact_file(cert_file, cert, sizeof(cert)) != 0) {
    return -1;
  }

  libhoth_security_version sv = htool_get_security_version(dev);
  switch (sv) {
    case LIBHOTH_SECURITY_V2:
      return exec_load_attestation_key(dev, wrapped_key, cert);
    // SECURITY_V3 not supported yet.
    default:
      fprintf(stderr, "SECURITY_V3 not supported yet\n");
      return -1;
  }
}

int htool_load_attestation_key_from_csr_v1(const struct htool_invocation* inv) {
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  const char* wrapped_key_file;
  if (htool_get_param_string(inv, "wrapped_key", &wrapped_key_file) != 0) {
    return -1;
  }

  const char* csr_file;
  if (htool_get_param_string(inv, "csr", &csr_file) != 0) {
    return -1;
  }

  if (strlen(wrapped_key_file) == 0 || strlen(csr_file) == 0) {
    fprintf(
        stderr,
        "Error: Both wrapped_key and csr files must be provided to load the "
        "Attestation Key.\n");
    return -1;
  }

  uint8_t wrapped_key[WRAPPED_ATTESTATION_KEY_SIZE] = {0};
  if (read_exact_file(wrapped_key_file, wrapped_key, sizeof(wrapped_key)) !=
      0) {
    return -1;
  }

  uint8_t csr[ATTESTATION_KEY_CSR_V1_SIZE] = {0};
  if (read_exact_file(csr_file, csr, sizeof(csr)) != 0) {
    return -1;
  }

  libhoth_security_version sv = htool_get_security_version(dev);
  switch (sv) {
    case LIBHOTH_SECURITY_V2:
      return exec_load_attestation_key_from_csr_v1(dev, wrapped_key, csr);
    // SECURITY_V3 not supported yet.
    default:
      fprintf(stderr, "SECURITY_V3 not supported yet\n");
      return -1;
  }
}

int htool_provision_attestation_key(const struct htool_invocation* inv) {
  (void)inv;
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  libhoth_security_version sv = htool_get_security_version(dev);
  switch (sv) {
    case LIBHOTH_SECURITY_V2: {
      int status = exec_unload_attestation_key(dev);
      if (status != 0) {
        return status;
      }

      uint8_t csr[ATTESTATION_KEY_CSR_V1_SIZE] = {0};
      uint8_t wrapped_key[WRAPPED_ATTESTATION_KEY_SIZE] = {0};
      status = exec_gen_attestation_key_v1(dev, csr, wrapped_key);
      if (status != 0) {
        return status;
      }

      return exec_load_attestation_key_from_csr_v1(dev, wrapped_key, csr);
    }
    // SECURITY_V3 not supported yet.
    default:
      fprintf(stderr, "SECURITY_V3 not supported yet\n");
      return -1;
  }
}
