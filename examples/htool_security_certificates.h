#ifndef LIBHOTH_EXAMPLES_HTOOL_SECURITY_CERTIFICATES_H_
#define LIBHOTH_EXAMPLES_HTOOL_SECURITY_CERTIFICATES_H_

#include <stdint.h>

#include "htool_security_v2_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

// Forward declaration
struct htool_invocation;
struct security_v2_param;

#define KEY_INFO_SIZE 4

#define ALIAS_KEY_V0_SIZE 192

#define ALIAS_KEY_V1_SIZE 224

#define MAX_ALIAS_KEY_SIZE ALIAS_KEY_V1_SIZE

struct key_cert_signature_header {
  uint32_t signature_version;
  uint32_t signature_purpose;
  uint8_t extension_header_type;
  uint8_t key_type;
  uint8_t key_op;
  uint8_t key_alg;
  uint8_t key_info[4];
  uint8_t cert_validity[16];
  uint64_t hw_id;
  uint16_t hw_cat;
  uint8_t reserved_0[2];
  uint32_t bootloader_tag;
  uint32_t fw_epoch;
  uint16_t fw_major_version;
  uint16_t pub_key_size;
  uint8_t reserved_1[8];
};

// Holds a signing request from the personalization firmware.
struct attestation_key_signing_request {
  struct key_cert_signature_header header;
  struct ec_p256_public_key pub_key;
  uint8_t cert_req_hmac[32];  // Assumed SHA256 HMAC
  struct ec_p256_signature sig;
  struct ec_p256_signature fpriv_sig;
  struct ec_p256_signature hpriv_sig;
  struct ec_p256_signature alias_key_sig;
};

struct key_wrapper {
  uint8_t wrapper_version;
  uint8_t wrapper_purpose;
  uint16_t reserved_0;
  uint32_t data_size;
  uint8_t iv[16];
  uint8_t hmac[32];
  uint8_t encrypted_data[32];
};

struct attestation_key_certificate {
  struct key_cert_signature_header signature_header;
  struct ec_p256_public_key public_key;
  struct ec_p256_signature signature;
};

typedef uint8_t key_info[KEY_INFO_SIZE];

struct device_id_certificate_header {
  uint32_t signature_version;
  uint32_t signature_purpose;
  uint8_t extension_header_type;
  uint8_t key_type;
  uint8_t key_op;
  uint8_t key_alg;
  uint8_t key_info[4];
  uint8_t cert_validity[16];
  uint8_t endorsement_key_id[16];
  uint64_t hw_id;
  uint16_t hw_cat;
  uint16_t signed_data_size;
  uint32_t bootloader_tag;
};

struct device_id_certificate {
  struct device_id_certificate_header header;
  struct ec_p256_public_key key;
  struct ec_p256_signature signature;
};

struct device_id_endorsement_certificate {
  uint8_t deviceid_cert_hash[32];
  struct ec_p256_public_key endorsement_rw_key;
  struct ec_p256_signature signature;
};

// Gets the Attestation Public Certificate
int htool_get_attestation_pub_cert(const struct htool_invocation* inv);
// Gets the Signed Attestation Public Certificate
int htool_get_signed_attestation_pub_cert(const struct htool_invocation* inv);
// Gets the Alias Key V0 Certificate
int htool_get_alias_key_v0_cert(const struct htool_invocation* inv);
// Gets the Alias Key V1 Certificate
int htool_get_alias_key_v1_cert(const struct htool_invocation* inv);
// Gets the Device ID Certificates
int htool_get_device_id_cert(const struct htool_invocation* inv);

#ifdef __cplusplus
}
#endif

#endif  // LIBHOTH_EXAMPLES_HTOOL_CERTIFICATES_H_
