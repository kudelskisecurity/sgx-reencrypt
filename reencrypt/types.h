#ifndef __TYPES_H__
#define __TYPES_H__

/* Public data types */

#include "tweetnacl/tweetnacl.h"
#include <stdint.h>

// return values for internal and external functions
typedef enum reencrypt_status {
    REENCRYPT_OK,
    REENCRYPT_FAILED,
    REENCRYPT_INVALID_INPUT,
    REENCRYPT_RDRAND_FAILED,
    REENCRYPT_NOT_READY,
    REENCRYPT_ERROR_KEYPAIR_REGENERATION,
    REENCRYPT_KEY_NOTFOUND,
    REENCRYPT_KEY_EXPIRED,
    REENCRYPT_NOT_AUTHORIZED,
    REENCRYPT_POLICY_FAILED,
    REENCRYPT_INCREASE_RESPONSE_SIZE,
    REENCRYPT_SEALING_FAILED
} reencrypt_status;

// client_id length has been specified to match NaCL public key size (32 bytes)
#define client_id_LEN 32
typedef uint8_t client_id[client_id_LEN];
// key_id length has been specified as 16 bytes (arbitrary)
#define key_id_LEN 16
typedef uint8_t key_id[key_id_LEN];
// policy types for keys-from/-to: keys from list, all
typedef enum policy_type { POLICY_LIST, POLICY_ALL } policy_type;
// policy structure
struct policy_t {
    // Keys-to-encrypt-from policy: ALL, LIST
    policy_type policy_from;
    // # keys accepted to encrypt from
    uint32_t n_keys_from;
    // Keys-to-encrypt-to policy: ALL, LIST
    policy_type policy_to;
    // # keys accepted to encrypt to
    uint32_t n_keys_to;
    // # client_ids authorized to use the key
    uint32_t n_authorized_clients;
    // dynamic arrays: stored at the end for easier serialization
    key_id *keys_from;
    key_id *keys_to;
    client_id *authorized_clients;
};
// key structure
struct keydata_t {
    uint32_t keylen;
    uint64_t expiration_date;
    uint8_t *key;
    struct policy_t policy;
};

#endif
