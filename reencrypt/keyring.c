#include "keyring.h"
#include "blake2/blake2.h"
#include "filesystem.h"
#include "reencrypt_t.h"
#include "sealing.h"
#include "serialize.h"
#include "types.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

reencrypt_status compute_key_id(const struct keydata_t *key, key_id id) {
    blake2b_state bs;
    // key_id needs to be set as hash(key_value|expiration)
    uint32_t tmplen = sizeof(key->key) + sizeof(key->expiration_date);
    uint8_t *tmp = (uint8_t *)malloc(tmplen);
    if (tmp == NULL)
        goto err;
    memcpy(tmp, key->key, sizeof(key->key));
    memcpy(&tmp[sizeof(key->key)], &key->expiration_date,
           sizeof(key->expiration_date));

    blake2b_init(&bs, 16);
    blake2b_update(&bs, tmp, tmplen);
    blake2b_final(&bs, id, sizeof(key_id));

    free(tmp);
    return REENCRYPT_OK;
err:
    return REENCRYPT_FAILED;
}

reencrypt_status get_key(const key_id id, struct keydata_t **key) {
    struct keydata_t *out = NULL;
    uint8_t *serialized = NULL, *aad = NULL, *sealed = NULL;
    size_t serializedlen, aadlen, sealedlen;
    char filename[33];
    int i;

    // compose filename string
    for (i = 0; i < 16; ++i) {
        snprintf(&filename[2 * i], 3, "%02X", id[i]);
    }
    // 1. load (no need to malloc; pointer to public data)
    if (fs_load(filename, 33, &sealed, &sealedlen) != REENCRYPT_OK) {
        goto err;
    }
    // 2. unseal
    if (unseal(sealed, sealedlen, &aad, &aadlen, &serialized, &serializedlen) !=
        REENCRYPT_OK) {
        goto err;
    }
    // did the operating system provide the right file?
    if (aadlen != sizeof(key_id)) {
        goto err;
    }
    if (memcmp(aad, id, sizeof(key_id))) {
        goto err;
    }
    // 3. deserialize
    if (key_deserialize(&out, serialized, serializedlen) != REENCRYPT_OK) {
        goto err;
    }

    *key = out;
    fs_free(sealed);
    free(aad);
    free(serialized);
    return REENCRYPT_OK;
err:
    fs_free(sealed);
    free(aad);
    free(serialized);
    return REENCRYPT_FAILED;
}

reencrypt_status put_key(const struct keydata_t *key, key_id id) {
    key_id tmpid;
    uint8_t *serialized = NULL, *sealed = NULL;
    size_t serializedlen, sealedlen;
    char filename[33];
    int i;

    // 1. serialize (malloc inside)
    if (key_serialize(key, &serialized, &serializedlen) != REENCRYPT_OK) {
        goto err;
    }

    // calculate key_id (hash key|expiration)
    if (compute_key_id(key, tmpid) != REENCRYPT_OK) {
        goto err;
    }
    // 2. seal (malloc inside)
    if (seal(tmpid, sizeof(key_id), serialized, serializedlen, &sealed,
             &sealedlen) != REENCRYPT_OK) {
        goto err;
    }
    // compose filename string
    for (i = 0; i < 16; ++i) {
        snprintf(&filename[2 * i], 3, "%02X", tmpid[i]);
    }
    // 3. store
    if (fs_store(filename, 33, sealed, sealedlen) != REENCRYPT_OK) {
        goto err;
    }
    // output filename
    memcpy(id, tmpid, 16);
    free(serialized);
    free(sealed);
    return REENCRYPT_OK;
err:
    free(serialized);
    free(sealed);
    return REENCRYPT_FAILED;
}

/* frees allocated memory */
void key_free(struct keydata_t *k) {
    if (k) {
        free(k->keys_from);
        free(k->keys_to);
        free(k->authorized_clients);
        free(k);
    }
}
