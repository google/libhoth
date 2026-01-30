#include "htool_security_tokens.h"

#include <assert.h>
#include <errno.h>
#include <stddef.h>
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
#include "transports/libhoth_device.h"

static int get_zero_challenge_nonce(struct nonce* challenge) {
  // Zero out the challenge nonce
  memset(challenge->nonce, 0, sizeof(challenge->nonce));
  return 0;
}

static int append_index_to_file_name(char* dest, size_t dest_size,
                                     const char* base_string, uint32_t number) {
  return snprintf(dest, dest_size, "%s%u", base_string, number);
}

static int htool_get_tokens_in_set(const struct htool_invocation* inv,
                                   uint32_t set_idx, uint8_t* data,
                                   uint32_t data_index,
                                   uint32_t* bytes_written) {
  int status = -1;
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  const char* token_output_file_base;
  if (htool_get_param_string(inv, "token_output", &token_output_file_base) !=
      0) {
    return -1;
  }
  char token_output_file[MAX_STRING_BUFFER_SIZE];
  int num_written =
      append_index_to_file_name(token_output_file, sizeof(token_output_file),
                                token_output_file_base, set_idx);
  if (num_written < 0 || (size_t)num_written >= sizeof(token_output_file)) {
    fprintf(stderr, "Failed to construct token output file path.\n");
    return -1;
  }

  FILE* token_output_ptr = NULL;
  FILE* signature_output_ptr = NULL;
  FILE* boot_nonce_output_ptr = NULL;

  if (data == NULL) {
    token_output_ptr = fopen(token_output_file, "wb");
    if (token_output_ptr == NULL) {
      printf("Error: %s, when attempting to open file: %s\n", strerror(errno),
             token_output_file);
      goto cleanup;
    }

    const char* signature_output_file_base;
    if (htool_get_param_string(inv, "token_signature_output",
                               &signature_output_file_base) != 0) {
      goto cleanup;
    }

    char signature_output_file[MAX_STRING_BUFFER_SIZE];
    num_written = append_index_to_file_name(
        signature_output_file, sizeof(signature_output_file),
        signature_output_file_base, set_idx);
    if (num_written < 0 ||
        (size_t)num_written >= sizeof(signature_output_file)) {
      fprintf(stderr, "Failed to construct signature output file path.\n");
      goto cleanup;
    }

    signature_output_ptr = fopen(signature_output_file, "wb");
    if (signature_output_ptr == NULL) {
      printf("Error: %s, when attempting to open file: %s\n", strerror(errno),
             signature_output_file);
      goto cleanup;
    }

    const char* boot_nonce_output_file_base;
    if (htool_get_param_string(inv, "token_boot_nonce_output",
                               &boot_nonce_output_file_base) != 0) {
      goto cleanup;
    }
    char boot_nonce_output_file[MAX_STRING_BUFFER_SIZE];
    num_written = append_index_to_file_name(
        boot_nonce_output_file, sizeof(boot_nonce_output_file),
        boot_nonce_output_file_base, set_idx);
    if (num_written < 0 ||
        (size_t)num_written >= sizeof(boot_nonce_output_file)) {
      fprintf(stderr, "Failed to construct boot nonce output file path.\n");
      goto cleanup;
    }

    boot_nonce_output_ptr = fopen(boot_nonce_output_file, "wb");
    if (boot_nonce_output_ptr == NULL) {
      printf("Error: %s, when attempting to open file: %s\n", strerror(errno),
             boot_nonce_output_file);
      goto cleanup;
    }
  }

  struct nonce challenge;
  if (get_zero_challenge_nonce(&challenge) != 0) {
    goto cleanup;
  }

  libhoth_security_version sv = htool_get_security_version(dev);
  switch (sv) {
    case LIBHOTH_SECURITY_V2: {
      // Send Get Token Set Request
      uint8_t request_storage_hdr[HOTH_SECURITY_V2_REQUEST_SIZE(2) +
                                  sizeof(set_idx) + sizeof(challenge)] = {};
      uint8_t response_storage_hdr[MAX_TOKEN_RESPONSE_SIZE] = {};

      struct security_v2_param request_params[] = {
          {
              .data = &set_idx,
              .size = sizeof(set_idx),
          },
          {
              .data = &challenge,
              .size = sizeof(challenge),
          }};
      const struct security_v2_serialized_param* tokens_param = NULL;
      const struct security_v2_serialized_param* sig_param = NULL;
      const struct security_v2_serialized_param* boot_nonce_param = NULL;
      const struct security_v2_serialized_param** response_params[] = {
          &tokens_param, &boot_nonce_param, &sig_param};
      // Gets the Tokens in the given Set
      int hoth_status = htool_exec_security_v2_serialized_cmd(
          dev, /*major=*/
          HOTH_PRV_CMD_HOTH_SECURITY_V2_TOKENS_MAJOR_COMMAND,
          /*minor=*/
          HOTH_PRV_CMD_HOTH_SECURITY_V2_GET_TOKENS_IN_SET_MINOR_COMMAND,
          /*base_command=*/HOTH_BASE_CMD(HOTH_PRV_CMD_HOTH_SECURITY_V2),
          SECURITY_V2_BUFFER_PARAM(request_storage_hdr), request_params,
          ARRAY_SIZE(request_params),
          SECURITY_V2_BUFFER_PARAM(response_storage_hdr), response_params,
          ARRAY_SIZE(response_params));
      if (hoth_status != 0) {
        printf(
            "Unexpected Error: Returned status %d, while trying to send "
            "command to get the Tokens for Set: %d\n",
            hoth_status, set_idx);
        status = hoth_status;
        goto cleanup;
      }

      if (!tokens_param || !sig_param || !boot_nonce_param) {
        printf("Failed to parse objects from response.\n");
        goto cleanup;
      }

      if (tokens_param->size > sizeof(response_storage_hdr)) {
        printf(
            "Returned token buffer (%u bytes) is larger than the provided "
            "buffer (%zu).\n",
            tokens_param->size, sizeof(response_storage_hdr));
        goto cleanup;
      }
      if ((tokens_param->size % TOKEN_BYTE_SIZE) != 0) {
        fprintf(stderr,
                "Returned token buffer (%u bytes) is not a "
                "multiple of token size (%u).\n",
                tokens_param->size, TOKEN_BYTE_SIZE);
        goto cleanup;
      }
      if (token_output_ptr && boot_nonce_output_ptr && signature_output_ptr) {
        // Write the tokens into the output file
        fwrite(tokens_param->value, tokens_param->size, NUM_OBJS_WRITTEN,
               token_output_ptr);
        fwrite(boot_nonce_param->value, boot_nonce_param->size,
               NUM_OBJS_WRITTEN, boot_nonce_output_ptr);
        fwrite(sig_param->value, sig_param->size, NUM_OBJS_WRITTEN,
               signature_output_ptr);
      } else {
        memcpy(data + data_index, tokens_param->value, tokens_param->size);
        *bytes_written += tokens_param->size;
        memcpy(data + data_index + *bytes_written, boot_nonce_param->value,
               boot_nonce_param->size);
        *bytes_written += boot_nonce_param->size;
        memcpy(data + data_index + *bytes_written, sig_param->value,
               sig_param->size);
        *bytes_written += sig_param->size;
      }
      break;
    }
    // SECURITY_V3 not supported.
    default:
      printf("SECURITY_V3 not supported.\n");
      goto cleanup;
  }
  status = 0;
cleanup:
  if (token_output_ptr) {
    fclose(token_output_ptr);
  }
  if (boot_nonce_output_ptr) {
    fclose(boot_nonce_output_ptr);
  }
  if (signature_output_ptr) {
    fclose(signature_output_ptr);
  }
  return status;
}

static int htool_get_token_set_count(const struct htool_invocation* inv,
                                     uint32_t* num_ids, uint8_t* data,
                                     uint32_t data_index) {
  int status = -1;
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  FILE* num_ids_ptr = NULL;
  FILE* signature_ptr = NULL;
  FILE* boot_nonce_ptr = NULL;

  if (data == NULL) {
    const char* num_ids_file;
    if (htool_get_param_string(inv, "token_count_output", &num_ids_file) != 0) {
      return -1;
    }

    num_ids_ptr = fopen(num_ids_file, "wb");
    if (num_ids_ptr == NULL) {
      printf("Error: %s, when attempting to open file: %s\n", strerror(errno),
             num_ids_file);
      goto cleanup;
    }

    const char* boot_nonce_file;
    if (htool_get_param_string(inv, "token_count_boot_nonce_output",
                               &boot_nonce_file) != 0) {
      goto cleanup;
    }

    boot_nonce_ptr = fopen(boot_nonce_file, "wb");
    if (boot_nonce_ptr == NULL) {
      printf("Error: %s, when attempting to open file: %s\n", strerror(errno),
             boot_nonce_file);
      goto cleanup;
    }

    const char* signature_file;
    if (htool_get_param_string(inv, "token_count_signature_output",
                               &signature_file) != 0) {
      goto cleanup;
    }

    signature_ptr = fopen(signature_file, "wb");
    if (signature_ptr == NULL) {
      printf("Error: %s, when attempting to open file: %s\n", strerror(errno),
             signature_file);
      goto cleanup;
    }
  }

  struct nonce challenge;
  if (get_zero_challenge_nonce(&challenge) != 0) {
    return status;
  }
  struct boot_nonce boot_nonce;
  struct detached_challenge_response_signature signature;

  libhoth_security_version sv = htool_get_security_version(dev);
  switch (sv) {
    case LIBHOTH_SECURITY_V2: {
      // Send Get Token Count Request
      uint8_t request_storage_hdr[HOTH_SECURITY_V2_REQUEST_SIZE(1) +
                                  sizeof(challenge)] = {};
      uint8_t response_storage_hdr[HOTH_SECURITY_V2_RESPONSE_SIZE(3) +
                                   sizeof(uint32_t) + sizeof(boot_nonce) +
                                   sizeof(signature)] = {};

      struct security_v2_param request_params[] = {
          {
              .data = &challenge,
              .size = sizeof(challenge),
          },
      };
      struct security_v2_param response_params[] = {
          {
              .data = num_ids,
              .size = sizeof(*num_ids),
          },
          {
              .data = &boot_nonce,
              .size = sizeof(boot_nonce),
          },
          {
              .data = &signature,
              .size = sizeof(signature),
          },

      };
      // Gets the number of Token Sets
      int hoth_status = htool_exec_security_v2_cmd(
          dev, /*major=*/
          HOTH_PRV_CMD_HOTH_SECURITY_V2_TOKENS_MAJOR_COMMAND,
          /*minor=*/
          HOTH_PRV_CMD_HOTH_SECURITY_V2_GET_TOKEN_SET_COUNT_MINOR_COMMAND,
          /*base_command=*/HOTH_BASE_CMD(HOTH_PRV_CMD_HOTH_SECURITY_V2),
          SECURITY_V2_BUFFER_PARAM(request_storage_hdr), request_params,
          ARRAY_SIZE(request_params),
          SECURITY_V2_BUFFER_PARAM(response_storage_hdr), response_params,
          ARRAY_SIZE(response_params));
      if (hoth_status != 0) {
        printf(
            "Unexpected Error: Returned status %d, while trying to send "
            "command to get the Token Set Count\n",
            hoth_status);
        status = hoth_status;
        goto cleanup;
      }
      if (num_ids_ptr && boot_nonce_ptr && signature_ptr) {
        // Return all of the values into their own output file
        fwrite(num_ids, sizeof(*num_ids), NUM_OBJS_WRITTEN, num_ids_ptr);
        fwrite(&boot_nonce, sizeof(boot_nonce), NUM_OBJS_WRITTEN,
               boot_nonce_ptr);
        fwrite(&signature, sizeof(signature), NUM_OBJS_WRITTEN, signature_ptr);
      } else {
        memcpy(data + data_index, num_ids, sizeof(*num_ids));
        memcpy(data + data_index + sizeof(*num_ids), &boot_nonce,
               sizeof(boot_nonce));
        memcpy(data + data_index + sizeof(*num_ids) + sizeof(boot_nonce),
               &signature, sizeof(signature));
      }
      break;
    }
    // SECURITY_V3 not supported.
    default:
      printf("SECURITY_V3 not supported.\n");
      goto cleanup;
  }
  status = 0;
cleanup:
  if (num_ids_ptr) {
    fclose(num_ids_ptr);
  }
  if (boot_nonce_ptr) {
    fclose(boot_nonce_ptr);
  }
  if (signature_ptr) {
    fclose(signature_ptr);
  }
  return status;
}

static int htool_get_token_set_info(const struct htool_invocation* inv,
                                    uint32_t set_idx, uint8_t* data,
                                    uint32_t data_index) {
  int status = -1;
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  struct nonce challenge;
  if (get_zero_challenge_nonce(&challenge) != 0) {
    return -1;
  }

  FILE* token_set_info_file_ptr = NULL;

  if (data == NULL) {
    const char* token_set_info_file_base;
    if (htool_get_param_string(inv, "token_set_info",
                               &token_set_info_file_base) != 0) {
      return -1;
    }
    char token_set_info_file[MAX_STRING_BUFFER_SIZE];
    int num_written = append_index_to_file_name(
        token_set_info_file, sizeof(token_set_info_file),
        token_set_info_file_base, set_idx);
    if (num_written < 0 || (size_t)num_written >= sizeof(token_set_info_file)) {
      fprintf(stderr, "Failed to construct token set info output file path.\n");
      return -1;
    }

    token_set_info_file_ptr = fopen(token_set_info_file, "wb");
    if (token_set_info_file_ptr == NULL) {
      printf("Error: %s, when attempting to open file: %s\n", strerror(errno),
             token_set_info_file);
      goto cleanup;
    }
  }

  struct boot_nonce boot_nonce;
  struct detached_challenge_response_signature signature;
  struct token_set_info info;

  libhoth_security_version sv = htool_get_security_version(dev);
  switch (sv) {
    case LIBHOTH_SECURITY_V2: {
      // Send Get Token Set Info Request
      uint8_t request_storage_hdr[HOTH_SECURITY_V2_REQUEST_SIZE(2) +
                                  sizeof(set_idx) + sizeof(challenge)] = {};
      uint8_t response_storage_hdr[HOTH_SECURITY_V2_RESPONSE_SIZE(3) +
                                   sizeof(info) + sizeof(boot_nonce) +
                                   sizeof(signature)] = {};

      struct security_v2_param request_params[] = {
          {
              .data = &set_idx,
              .size = sizeof(set_idx),
          },
          {
              .data = &challenge,
              .size = sizeof(challenge),
          },
      };
      struct security_v2_param response_params[] = {
          {
              .data = &info,
              .size = sizeof(info),
          },
          {
              .data = &boot_nonce,
              .size = sizeof(boot_nonce),
          },
          {
              .data = &signature,
              .size = sizeof(signature),
          },

      };
      // Gets the Token Set Info
      int hoth_status = htool_exec_security_v2_cmd(
          dev, /*major=*/
          HOTH_PRV_CMD_HOTH_SECURITY_V2_TOKENS_MAJOR_COMMAND,
          /*minor=*/
          HOTH_PRV_CMD_HOTH_SECURITY_V2_GET_TOKEN_SET_INFO_MINOR_COMMAND,
          /*base_command=*/HOTH_BASE_CMD(HOTH_PRV_CMD_HOTH_SECURITY_V2),
          SECURITY_V2_BUFFER_PARAM(request_storage_hdr), request_params,
          ARRAY_SIZE(request_params),
          SECURITY_V2_BUFFER_PARAM(response_storage_hdr), response_params,
          ARRAY_SIZE(response_params));
      if (hoth_status != 0) {
        printf(
            "Unexpected Error: Returned status %d, while trying to send "
            "command to get the Token Set Info\n",
            hoth_status);
        status = hoth_status;
        goto cleanup;
      }
      // Return token set info into their own output file
      if (token_set_info_file_ptr) {
        fwrite(&info, sizeof(info), NUM_OBJS_WRITTEN, token_set_info_file_ptr);
      } else {
        memcpy(data + data_index, &info, sizeof(info));
      }
      break;
    }
    // SECURITY_V3 not supported.
    default:
      printf("SECURITY_V3 not supported.\n");
      goto cleanup;
  }
  status = 0;
cleanup:
  if (token_set_info_file_ptr) {
    fclose(token_set_info_file_ptr);
  }
  return status;
}

static int htool_fetch_single_attestation_file(
    const struct htool_invocation* inv, const char* filename) {
  int status = -1;
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }
  // Binary file that contains all attestation data
  uint8_t data[MAX_ATTESTATION_SIZE];
  uint32_t data_index = 0;

  // Get Token Set Count
  uint32_t num_ids = 0;
  if (data_index >= sizeof(data)) {
    printf("Error: Calculated data_index: %d >= size of data buffer: %ld\n",
           data_index, sizeof(data));
    return status;
  }

  status = htool_get_token_set_count(inv, &num_ids, data, data_index);
  if (status != 0) {
    return status;
  }
  data_index += sizeof(num_ids) + sizeof(struct boot_nonce) +
                sizeof(struct detached_challenge_response_signature);

  FILE* attestation_file_ptr = NULL;

  if (filename == NULL) {
    printf("Error: Attestation filename is NULL.\n");
    goto cleanup;
  }

  attestation_file_ptr = fopen(filename, "wb");
  if (attestation_file_ptr == NULL) {
    printf("Error: %s, when attempting to open attestation file: %s\n",
           strerror(errno), filename);
    goto cleanup;
  }

  libhoth_security_version sv = htool_get_security_version(dev);
  switch (sv) {
    case LIBHOTH_SECURITY_V2: {
      // Copy the num_id into the data buffer
      for (int i = 0; i < num_ids; i++) {
        // The amount of bytes written for a token set
        uint32_t bytes_written = 0;

        if (data_index >= sizeof(data)) {
          printf(
              "Error: Calculated data_index: %d >= size of data buffer: %ld\n",
              data_index, sizeof(data));
          goto cleanup;
        }
        // Get Tokens in Set
        status =
            htool_get_tokens_in_set(inv, i, data, data_index, &bytes_written);
        if (status != 0) {
          return status;
        }
        data_index += bytes_written;

        if (data_index >= sizeof(data)) {
          printf(
              "Error: Calculated data_index: %d >= size of data buffer: %ld\n",
              data_index, sizeof(data));
          goto cleanup;
        }
        // Get Token Set Info
        status = htool_get_token_set_info(inv, i, data, data_index);
        if (status != 0) {
          return status;
        }
        data_index += sizeof(struct token_set_info);
      }
      // Return data buffer into their own output file
      fwrite(data, data_index, NUM_OBJS_WRITTEN, attestation_file_ptr);
      printf("Attestation written to : %s\n", filename);
      break;
    }
    // SECURITY_V3 not supported yet.
    default:
      printf("SECURITY_V3 not supported yet\n");
      goto cleanup;
  }
  status = 0;
cleanup:
  if (attestation_file_ptr) {
    fclose(attestation_file_ptr);
  }
  return status;
}

int htool_fetch_attestation(const struct htool_invocation* inv) {
  int status = -1;

  const char* attestation_file;
  if (htool_get_param_string(inv, "attestation_file", &attestation_file) != 0) {
    // Failed to get attestation_file flag
    return status;
  }
  // Get the attestation_file flag, if the flag is not provided retrieve the
  // individual attestation fields.
  if (strlen(attestation_file) == 0) {
    // Get Token Set Count
    uint32_t num_ids = 0;
    status = htool_get_token_set_count(inv, &num_ids, /*data=*/NULL,
                                       /*data_index=*/0);
    if (status != 0) {
      return status;
    }

    for (int i = 0; i < num_ids; i++) {
      // Get Tokens in Set
      status = htool_get_tokens_in_set(inv, i, /*data=*/NULL, /*data_index=*/0,
                                       /*bytes_written=*/NULL);
      if (status != 0) {
        return status;
      }

      // Get Token Set Info
      status =
          htool_get_token_set_info(inv, i, /*data=*/NULL, /*data_index=*/0);
      if (status != 0) {
        return status;
      }
    }
  } else {
    // If the attestation_flag is provided return the entire attestation
    // in a single file.
    status = htool_fetch_single_attestation_file(inv, attestation_file);
    if (status != 0) {
      return status;
    }
  }

  return status;
}
