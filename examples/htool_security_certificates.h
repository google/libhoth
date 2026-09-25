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

#define NUM_OF_CERTS_WRITTEN 1

#define ATTESTATION_CERT_SIZE 192

#define DEVICE_CERT_SIZE 192

#define DEVICE_ENDORSEMENT_CERT_SIZE 160

#define ATTESTATION_KEY_CSR_V1_SIZE 256

#define ATTESTATION_KEY_CSR_V2_SIZE 192

#define WRAPPED_ATTESTATION_KEY_SIZE 88

// Gets the Attestation Public Certificate
int htool_get_attestation_pub_cert(const struct htool_invocation* inv);
// Gets the Signed Attestation Public Certificate
int htool_get_signed_attestation_pub_cert(const struct htool_invocation* inv);
// Gets the Alias Key Certificate
int htool_get_alias_key_cert(const struct htool_invocation* inv);
// Gets the Device ID Certificates
int htool_get_device_id_cert(const struct htool_invocation* inv);
// Unloads the Attestation Key
int htool_unload_attestation_key(const struct htool_invocation* inv);
// Generates an Attestation Key using CSR v1
int htool_gen_attestation_key_v1(const struct htool_invocation* inv);
// Generates an Attestation Key using CSR v2
int htool_gen_attestation_key_v2(const struct htool_invocation* inv);
// Loads an Attestation Key from a CA-signed certificate
int htool_load_attestation_key(const struct htool_invocation* inv);
// Loads a self-signed Attestation Key from CSR v1
int htool_load_attestation_key_from_csr_v1(const struct htool_invocation* inv);
// Provisions a self-signed Attestation Key
int htool_provision_attestation_key(const struct htool_invocation* inv);

#ifdef __cplusplus
}
#endif

#endif  // LIBHOTH_EXAMPLES_HTOOL_CERTIFICATES_H_
