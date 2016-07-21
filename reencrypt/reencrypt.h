#pragma once

#include "ciphers/aes128gcm.h"
#include "filesystem.h"
#include "keyring.h"
#include "nacl_box.h"
#include "policy.h"
#include "reencrypt_t.h"
#include "request.h"
#include "sealing.h"
#include "sgx_trts.h"
#include "tweetnacl/tweetnacl.h"
#include "types.h"
#include <sgx_spinlock.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct reencrypt_context {
    unsigned char pk[crypto_box_PUBLICKEYBYTES];
    unsigned char sk[crypto_box_SECRETKEYBYTES];
    int ready;
};

// encryption and decryption functions
reencrypt_status encrypt(uint8_t **c, size_t *clen, const uint8_t *m,
                         const size_t mlen, const struct keydata_t *key);
reencrypt_status decrypt(uint8_t **m, size_t *mlen, const uint8_t *c,
                         const size_t clen, const struct keydata_t *key);
