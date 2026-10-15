#ifndef LIBHOTH_EXAMPLES_HTOOL_SECURITY_TOKENS_H_
#define LIBHOTH_EXAMPLES_HTOOL_SECURITY_TOKENS_H_

#include <stdint.h>

#include "htool_security_v2_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

// Forward declaration
struct htool_invocation;

#define MAX_TOKEN_RESPONSE_SIZE 1024

#define TOKEN_BYTE_SIZE 16

#define NONCE_SIZE 16

#define MAX_ATTESTATION_SIZE 2048

#define MAX_STRING_BUFFER_SIZE 2048

#define NUM_OBJS_WRITTEN 1

struct nonce {
  uint8_t nonce[NONCE_SIZE];
};

struct boot_nonce {
  struct nonce nonce;
};

struct challenge_response_header {
  uint32_t signature_version;
  uint32_t signature_purpose;
  uint8_t major_command;
  uint8_t minor_command;
  uint16_t signed_response_length;
  uint16_t hw_cat;
  uint8_t reserved_0[2];
  uint64_t hw_id;
  struct nonce verifier_nonce;
  uint8_t reserved_1[24];
};

struct detached_challenge_response_signature {
  struct challenge_response_header signature_header;
  struct ec_p256_signature signature;
};

struct token_set_info {
  uint16_t category;
  uint16_t num_tokens;
  uint8_t is_frozen;
  uint8_t reserved_0[3];
};

int htool_fetch_attestation(const struct htool_invocation* inv);

#ifdef __cplusplus
}
#endif

#endif  // LIBHOTH_EXAMPLES_HTOOL_SECURITY_TOKENS_H_
