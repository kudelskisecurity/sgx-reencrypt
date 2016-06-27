#include "keyring.h"
#include "blake2/blake2.h"
#include "filesystem.h"
#include "reencrypt_t.h"
#include "sealing.h"
#include "types.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

reencrypt_status compute_key_id(const struct key_t *key, key_id id) {
    blake2b_state bs;
    // key_id needs to be set as hash(key_value|expiration)
    uint32_t tmplen =
        key->keylen + sizeof(key->expiration_date);
    uint8_t *tmp = (uint8_t *)malloc(tmplen);
    if (tmp == NULL)
        goto err;
    memcpy(tmp, key->key, key->keylen);
    memcpy(&tmp[key->keylen], &key->expiration_date,
           sizeof(key->expiration_date));

    blake2b_init(&bs, 16);
    blake2b_update(&bs, tmp, tmplen);
    blake2b_final(&bs, id, sizeof(key_id));

    free(tmp);
    return REENCRYPT_OK;
err:
    return REENCRYPT_FAILED;
}

reencrypt_status get_key(const key_id id, struct key_t **key) {
    struct key_t *out = NULL;
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
    key_deserialize(&out, serialized, serializedlen);

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

reencrypt_status put_key(const struct key_t *key, key_id id) {
    key_id tmpid;
    uint8_t *serialized = NULL, *sealed = NULL;
    size_t serializedlen, sealedlen;
    char filename[33];
    int i;

    // 1. serialize (malloc inside)
    key_serialize(key, &serialized, &serializedlen);
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

/* serialize a key
        input:
                k, pointer to key

        output:
                blob, pointer to pointer to serialized key. allocated inside,
                          needs to be freed
                bloblen, pointer to blob length
*/
reencrypt_status key_serialize(const struct key_t *k, uint8_t **blob,
                               size_t *bloblen) {
    uint8_t *policy_pos = NULL;
    uint8_t *temp;
    size_t keysfromsize, keystosize, authsize;
    // calculate total size
    size_t size = sizeof(uint32_t) + sizeof(uint64_t) +
                  2 * sizeof(policy_type) + 3 * sizeof(uint32_t) + k->keylen +
                  k->policy.n_keys_from * sizeof(key_id) +
                  k->policy.n_keys_to * sizeof(key_id) +
                  k->policy.n_authorized_clients * sizeof(client_id);

    // allocate enough memory for this thing
    temp = (uint8_t *)malloc(size);
    if (temp == NULL)
        goto err;
    // pack data
    memcpy(temp + offsetof(struct key_t, keylen), &k->keylen,
           sizeof(k->keylen));
    memcpy(temp + offsetof(struct key_t, expiration_date), &k->expiration_date,
           sizeof(k->expiration_date));
    // copy key value
    memcpy(temp + offsetof(struct key_t, key), k->key, k->keylen);
    // policy serialize: doing it here. should we bring policy attrs to key_t?
    policy_pos = temp + offsetof(struct key_t, key) + k->keylen;
    // copy every value before keys_from
    memcpy(policy_pos, &k->policy, offsetof(struct policy_t, keys_from));
    // copy dynamic arrays
    keysfromsize = k->policy.n_keys_from * sizeof(key_id);
    keystosize = k->policy.n_keys_to * sizeof(key_id);
    authsize = k->policy.n_authorized_clients * sizeof(client_id);
    memcpy(policy_pos + offsetof(struct policy_t, keys_from),
           k->policy.keys_from, keysfromsize);
    memcpy(policy_pos + offsetof(struct policy_t, keys_from) + keysfromsize,
           k->policy.keys_to, keystosize);
    memcpy(policy_pos + offsetof(struct policy_t, keys_from) + keysfromsize +
               keystosize,
           k->policy.authorized_clients, authsize);
    // we're done; output blob and size
    *blob = temp;
    *bloblen = size;

    return REENCRYPT_OK;
err:
    return REENCRYPT_FAILED;
};

/* deserialize a key
        input:
                blob, pointer to serialized key
                bloblen, pointer to blob length

        output:
                k, pointer to pointer to key. allocated inside, needs to be
   freed
*/
reencrypt_status key_deserialize(struct key_t **k, const uint8_t *blob,
                                 const size_t bloblen) {
    uint8_t *policy_pos = NULL;
    size_t keysfromsize, keystosize, authsize;
    struct key_t *temp;
    size_t required_size = sizeof(uint32_t) + sizeof(uint64_t);
    // safety check
    if (bloblen < required_size)
        goto err;

    temp = (struct key_t *)malloc(sizeof(struct key_t));
    if (temp == NULL)
        goto err;
    // unpack data
    memcpy(&(temp->keylen), blob + offsetof(struct key_t, keylen),
           sizeof(uint32_t));
    memcpy(&(temp->expiration_date),
           blob + offsetof(struct key_t, expiration_date), sizeof(uint64_t));
    // update safety check
    required_size += temp->keylen;
    if (bloblen < required_size)
        goto err;
    // allocate key buffer
    temp->key = (uint8_t *)malloc(temp->keylen);
    if (temp->key == NULL)
        goto err;
    // copy key
    memcpy(temp->key, blob + offsetof(struct key_t, key), temp->keylen);

    // deserialize policy
    policy_pos = (uint8_t *)blob + required_size;
    // update safety checks
    required_size += 2 * sizeof(policy_type) + 3 * sizeof(uint32_t);
    if (bloblen < required_size)
        goto err;
    // copy policy types and counters
    memcpy(&temp->policy.policy_from,
           policy_pos + offsetof(struct policy_t, policy_from),
           sizeof(policy_type));
    memcpy(&temp->policy.n_keys_from,
           policy_pos + offsetof(struct policy_t, n_keys_from),
           sizeof(uint32_t));
    memcpy(&temp->policy.policy_to,
           policy_pos + offsetof(struct policy_t, policy_to),
           sizeof(policy_type));
    memcpy(&temp->policy.n_keys_to,
           policy_pos + offsetof(struct policy_t, n_keys_to), sizeof(uint32_t));
    memcpy(&temp->policy.n_authorized_clients,
           policy_pos + offsetof(struct policy_t, n_authorized_clients),
           sizeof(uint32_t));
    // calculate required memory for policy arrays
    keysfromsize = temp->policy.n_keys_from * sizeof(key_id);
    keystosize = temp->policy.n_keys_to * sizeof(key_id);
    authsize = temp->policy.n_authorized_clients * sizeof(client_id);
    // allocate policy arrays
    temp->policy.keys_from = malloc(keysfromsize);
    if (temp->policy.keys_from == NULL)
        goto err;
    temp->policy.keys_to = malloc(keystosize);
    if (temp->policy.keys_to == NULL)
        goto err;
    temp->policy.authorized_clients = malloc(authsize);
    if (temp->policy.authorized_clients == NULL)
        goto err;
    // update safety checks
    // this is last one - check required and actual size are equal
    required_size += keysfromsize + keystosize + authsize;
    if (bloblen != required_size)
        goto err;
    // copy dynamic arrays
    memcpy(temp->policy.keys_from,
           policy_pos + offsetof(struct policy_t, keys_from), keysfromsize);
    memcpy(temp->policy.keys_to,
           policy_pos + offsetof(struct policy_t, keys_from) + keysfromsize,
           keystosize);
    memcpy(temp->policy.authorized_clients,
           policy_pos + offsetof(struct policy_t, keys_from) + keysfromsize +
               keystosize,
           authsize);

    // we're done: output new key
    *k = temp;
    return REENCRYPT_OK;
err:
    key_free(temp);
    return REENCRYPT_FAILED;
}

/* frees allocated memory */
void key_free(struct key_t *k) {
    if (k) {
        free(k->policy.keys_from);
        free(k->policy.keys_to);
        free(k->policy.authorized_clients);
        free(k);
    }
}
