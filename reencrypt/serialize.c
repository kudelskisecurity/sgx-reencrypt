#include "types.h"
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* serialize a key
        input:
                k, pointer to key

        output:
                blob, pointer to pointer to serialized key. allocated inside,
                          needs to be freed
                bloblen, pointer to blob length
*/
reencrypt_status key_serialize(const struct keydata_t *k, uint8_t **blob,
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
    memcpy(temp + offsetof(struct keydata_t, keylen), &k->keylen,
           sizeof(k->keylen));
    memcpy(temp + offsetof(struct keydata_t, expiration_date), &k->expiration_date,
           sizeof(k->expiration_date));
    // copy key value
    memcpy(temp + offsetof(struct keydata_t, key), k->key, k->keylen);
    // policy serialize: doing it here. should we bring policy attrs to keydata_t?
    policy_pos = temp + offsetof(struct keydata_t, key) + k->keylen;
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
reencrypt_status key_deserialize(struct keydata_t **k, const uint8_t *blob,
                                 const size_t bloblen) {
    uint8_t *policy_pos = NULL;
    size_t keysfromsize, keystosize, authsize;
    struct keydata_t *temp;
    size_t required_size = sizeof(uint32_t) + sizeof(uint64_t);
    // safety check
    if (bloblen < required_size)
        goto err;

    temp = (struct keydata_t *)malloc(sizeof(struct keydata_t));
    if (temp == NULL)
        goto err;
    // unpack data
    memcpy(&(temp->keylen), blob + offsetof(struct keydata_t, keylen),
           sizeof(uint32_t));
    memcpy(&(temp->expiration_date),
           blob + offsetof(struct keydata_t, expiration_date), sizeof(uint64_t));
    // update safety check
    required_size += temp->keylen;
    if (bloblen < required_size)
        goto err;
    // allocate key buffer
    temp->key = (uint8_t *)malloc(temp->keylen);
    if (temp->key == NULL)
        goto err;
    // copy key
    memcpy(temp->key, blob + offsetof(struct keydata_t, key), temp->keylen);

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
    // TODO: properly handle memory free'ing here!
    // key_free(temp);
    return REENCRYPT_FAILED;
}

