#include "htool_security_tokens.h"

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "host_commands.h"
#include "htool_security_v2.h"
#include "htool.h"
#include "htool_cmd.h"
#include "htool_macros.h"
#include "htool_security_version.h"
#include "transports/libhoth_device.h"
#include "protocol/host_cmd.h"

static int get_rand_challenge_nonce(struct nonce* challenge) {
  // Zero out the challenge
  memset(challenge->nonce, 0, sizeof(challenge->nonce));
  return 0;
}

int htool_get_tokens_in_set(const struct htool_invocation* inv) {
  int status = -1;
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  const char* token_output_file;
  if (htool_get_param_string(inv, "token_output", &token_output_file) != 0) {
    return -1;
  }

  FILE* token_output_ptr = NULL;
  FILE* signature_output_ptr = NULL;
  FILE* boot_nonce_output_ptr = NULL;

  token_output_ptr = fopen(token_output_file, "wb");
  if (token_output_ptr == NULL) {
    printf("Error: %s, when attempting to open file: %s\n", strerror(errno),
           token_output_file);
    goto cleanup;
  }

  const char* signature_output_file;
  if (htool_get_param_string(inv, "signature_output", &signature_output_file) != 0) {
    return -1;
  }

  signature_output_ptr = fopen(signature_output_file, "wb");
  if (signature_output_ptr == NULL) {
    printf("Error: %s, when attempting to open file: %s\n", strerror(errno),
           signature_output_file);
    goto cleanup;
  }

  const char* boot_nonce_output_file;
  if (htool_get_param_string(inv, "boot_nonce_output", &boot_nonce_output_file) != 0) {
    return -1;
  }

  boot_nonce_output_ptr = fopen(boot_nonce_output_file, "wb");
  if (boot_nonce_output_ptr == NULL) {
    printf("Error: %s, when attempting to open file: %s\n", strerror(errno),
           boot_nonce_output_file);
    goto cleanup;
  }

  struct nonce challenge;
  if (get_rand_challenge_nonce(&challenge) != 0) {
    goto cleanup;
  }

  uint32_t set_idx;
  if (htool_get_param_u32(inv, "set_index", &set_idx) != 0) {
    goto cleanup;    
  }

  libhoth_security_version sv = htool_get_security_version(dev);
  switch (sv) {
    case LIBHOTH_SECURITY_V2: {
      // Send Get Token Set Request
      uint8_t request_storage_hdr[HOTH_SECURITY_V2_REQUEST_SIZE(2) + sizeof(set_idx) + sizeof(challenge)] = {};
      uint8_t response_storage_hdr[MAX_TOKEN_RESPONSE_SIZE] = {};

      struct security_v2_param request_params[] = {
          {
              .data = &set_idx,
              .size = sizeof(set_idx),
          },
          {
              .data = &challenge,
              .size = sizeof(challenge),
          }
      };
      const struct security_v2_serialized_param* tokens_param = NULL;
      const struct security_v2_serialized_param* sig_param = NULL;
      const struct security_v2_serialized_param* boot_nonce_param = NULL;
      const struct security_v2_serialized_param** response_params[] = {
          &tokens_param, &boot_nonce_param, &sig_param
      };
      // Gets the Tokens in the given Set
      int hoth_status = htool_exec_security_v2_serialized_cmd(
          dev, /*major=*/
          HOTH_PRV_CMD_HOTH_SECURITY_V2_TOKENS_MAJOR_COMMAND,
          /*minor=*/HOTH_PRV_CMD_HOTH_SECURITY_V2_GET_TOKENS_IN_SET_MINOR_COMMAND,
          /*base_command=*/HOTH_BASE_CMD(HOTH_PRV_CMD_HOTH_SECURITY_V2),
          SECURITY_V2_BUFFER_PARAM(request_storage_hdr), request_params, ARRAY_SIZE(request_params),
          SECURITY_V2_BUFFER_PARAM(response_storage_hdr), response_params, ARRAY_SIZE(response_params));
      if (hoth_status != 0) {
        printf(
              "Unexpected Error: Returned status %d, while trying to send "
              "command to get the Tokens for Set: %d\n",
              hoth_status, set_idx);
        status = hoth_status;
        goto cleanup;
      }

      if (!tokens_param) {
        printf("Failed to parse tokens from response.\n");
        goto cleanup;
      }

      if (tokens_param->size > sizeof(response_storage_hdr)) {
        printf("Returned token buffer (%u bytes) is larger than the provided "
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

      // Write the tokens into the output file
      fwrite(tokens_param->value, tokens_param->size, sizeof(uint8_t), token_output_ptr);
      fwrite(boot_nonce_param->value, boot_nonce_param->size, sizeof(uint8_t), boot_nonce_output_ptr);
      fwrite(sig_param->value, sig_param->size, sizeof(uint8_t), signature_output_ptr);
      break;
    }
    // SECURITY_V3 not supported yet.
    default:
      printf("SECURITY_V3 not supported yet\n");
      return -1;
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

int htool_get_token_set_count(const struct htool_invocation* inv) {
  int status = -1;
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  const char* num_ids_file;
  if (htool_get_param_string(inv, "num_ids_output", &num_ids_file) != 0) {
    return -1;
  }

  FILE* num_ids_ptr = NULL;
  FILE* signature_ptr = NULL;
  FILE* boot_nonce_ptr = NULL;

  num_ids_ptr = fopen(num_ids_file, "wb");
  if (num_ids_ptr == NULL) {
    printf("Error: %s, when attempting to open file: %s\n", strerror(errno),
           num_ids_file);
    goto cleanup;
  }

  const char* boot_nonce_file;
  if (htool_get_param_string(inv, "boot_nonce_output", &boot_nonce_file) != 0) {
    return -1;
  }

  boot_nonce_ptr = fopen(boot_nonce_file, "wb");
  if (boot_nonce_ptr == NULL) {
    printf("Error: %s, when attempting to open file: %s\n", strerror(errno),
           boot_nonce_file);
    goto cleanup;
  }

  const char* signature_file;
  if (htool_get_param_string(inv, "signature_output", &signature_file) != 0) {
    return -1;
  }

  signature_ptr = fopen(signature_file, "wb");
  if (signature_ptr == NULL) {
    printf("Error: %s, when attempting to open file: %s\n", strerror(errno),
           signature_file);
    goto cleanup;
  }

  struct nonce challenge;
  if (get_rand_challenge_nonce(&challenge) != 0) {
    goto cleanup;
  }
  struct boot_nonce boot_nonce;
  struct detached_challenge_response_signature signature;
  uint32_t num_ids;
  
  libhoth_security_version sv = htool_get_security_version(dev);
  switch (sv) {
    case LIBHOTH_SECURITY_V2: {
      // Send Get Token Count Request
      uint8_t request_storage_hdr[HOTH_SECURITY_V2_REQUEST_SIZE(1) + sizeof(struct nonce)] = {};
      uint8_t response_storage_hdr[HOTH_SECURITY_V2_RESPONSE_SIZE(3) + sizeof(uint32_t) 
                              + sizeof(struct boot_nonce) + sizeof(struct detached_challenge_response_signature)] = {};

      struct security_v2_param request_params[] = {
          {
              .data = &challenge,
              .size = sizeof(struct nonce),
          },
      };
      struct security_v2_param response_params[] = {
          {
              .data = &num_ids,
              .size = sizeof(uint32_t),
          },
          {
              .data = &boot_nonce,
              .size = sizeof(struct boot_nonce),
          },
          {
              .data = &signature,
              .size = sizeof(struct detached_challenge_response_signature),
          },

      };
      // Gets the number of Token Sets
      int hoth_status = htool_exec_security_v2_cmd(
          dev, /*major=*/
          HOTH_PRV_CMD_HOTH_SECURITY_V2_TOKENS_MAJOR_COMMAND,
          /*minor=*/HOTH_PRV_CMD_HOTH_SECURITY_V2_GET_TOKEN_SET_COUNT_MINOR_COMMAND,
          /*base_command=*/HOTH_BASE_CMD(HOTH_PRV_CMD_HOTH_SECURITY_V2),
          SECURITY_V2_BUFFER_PARAM(request_storage_hdr), request_params, ARRAY_SIZE(request_params),
          SECURITY_V2_BUFFER_PARAM(response_storage_hdr), response_params, ARRAY_SIZE(response_params));
      if (hoth_status != 0) {
        printf(
              "Unexpected Error: Returned status %d, while trying to send "
              "command to get the Token Set Count\n",
              hoth_status);
        status = hoth_status;
        goto cleanup;
      }
      // Return all of the values into their own output file 
      fwrite(&num_ids, sizeof(uint32_t), sizeof(uint8_t), num_ids_ptr);
      fwrite(&boot_nonce, sizeof(struct boot_nonce), sizeof(uint8_t), boot_nonce_ptr);
      fwrite(&signature, sizeof(struct detached_challenge_response_signature), sizeof(uint8_t), signature_ptr);
      break;
    }
    // SECURITY_V3 not supported yet.
    default:
      printf("SECURITY_V3 not supported yet\n");
      return -1;
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

int htool_get_token_set_info(const struct htool_invocation* inv) {
  int status = -1;
  struct libhoth_device* dev = htool_libhoth_device();
  if (!dev) {
    return -1;
  }

  uint32_t set_idx;
  if (htool_get_param_u32(inv, "set_index", &set_idx) != 0) {
    return -1;    
  }
  
  struct nonce challenge;
  if (get_rand_challenge_nonce(&challenge) != 0) {
    return -1;
  }

  const char* token_set_info_file;
  if (htool_get_param_string(inv, "token_set_info", &token_set_info_file) != 0) {
    return -1;
  }

  FILE* token_set_info_file_ptr = NULL;

  token_set_info_file_ptr = fopen(token_set_info_file, "wb");
  if (token_set_info_file_ptr == NULL) {
    printf("Error: %s, when attempting to open file: %s\n", strerror(errno),
           token_set_info_file);
    goto cleanup;
  }

  struct boot_nonce boot_nonce;
  struct detached_challenge_response_signature signature;
  struct token_set_info info;
  
  libhoth_security_version sv = htool_get_security_version(dev);
  switch (sv) {
    case LIBHOTH_SECURITY_V2: {
      // Send Get Token Set Info Request
      uint8_t request_storage_hdr[HOTH_SECURITY_V2_REQUEST_SIZE(2) + sizeof(uint32_t) + sizeof(struct nonce)] = {};
      uint8_t response_storage_hdr[HOTH_SECURITY_V2_RESPONSE_SIZE(3) + sizeof(struct token_set_info) 
                                + sizeof(struct boot_nonce) + sizeof(struct detached_challenge_response_signature)] = {};

      struct security_v2_param request_params[] = {
          {
              .data = &set_idx,
              .size = sizeof(uint32_t),
          },
          {
              .data = &challenge,
              .size = sizeof(struct nonce),
          },
      };
      struct security_v2_param response_params[] = {
          {
              .data = &info,
              .size = sizeof(struct token_set_info),
          },
          {
              .data = &boot_nonce,
              .size = sizeof(struct boot_nonce),
          },
          {
              .data = &signature,
              .size = sizeof(struct detached_challenge_response_signature),
          },

      };
      // Gets the Token Set Info
      int hoth_status = htool_exec_security_v2_cmd(
          dev, /*major=*/
          HOTH_PRV_CMD_HOTH_SECURITY_V2_TOKENS_MAJOR_COMMAND,
          /*minor=*/HOTH_PRV_CMD_HOTH_SECURITY_V2_GET_TOKEN_SET_INFO_MINOR_COMMAND,
          /*base_command=*/HOTH_BASE_CMD(HOTH_PRV_CMD_HOTH_SECURITY_V2),
          SECURITY_V2_BUFFER_PARAM(request_storage_hdr), request_params, ARRAY_SIZE(request_params),
          SECURITY_V2_BUFFER_PARAM(response_storage_hdr), response_params, ARRAY_SIZE(response_params));
      if (hoth_status != 0) {
        printf(
              "Unexpected Error: Returned status %d, while trying to send "
              "command to get the Token Set Info\n",
              hoth_status);
        status = hoth_status;
        goto cleanup;
      }
      // Return token set info into their own output file 
      fwrite(&info, sizeof(struct token_set_info), sizeof(uint8_t), token_set_info_file_ptr);
      break;
    }
    // SECURITY_V3 not supported yet.
    default:
      printf("SECURITY_V3 not supported yet\n");
      return -1;
  }
  status = 0;
cleanup:
  if (token_set_info_file_ptr) {
    fclose(token_set_info_file_ptr);
  }
  return status;

}
