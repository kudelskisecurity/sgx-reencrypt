#include "make_this_a_lib.h"
#include "reencrypt.h"
#include "tweetnacl/tweetnacl.h"
#include <stdlib.h>
#include <string.h>

reencrypt_status key_serialize(const struct key_t *k, uint8_t **blob,
                               uint32_t *bloblen) {
    uint8_t *policy_pos = NULL;
    uint8_t *temp;
    uint32_t keysfromsize, keystosize, authsize;
    // calculate total size
    uint32_t size = sizeof(cipher_t) + sizeof(uint32_t) + sizeof(uint64_t) +
                    2 * sizeof(policy_type) + 3 * sizeof(uint32_t) + k->keylen +
                    k->policy.n_keys_from * sizeof(key_id) +
                    k->policy.n_keys_to * sizeof(key_id) +
                    k->policy.n_authorized_clients * sizeof(client_id);

    // allocate enough memory for this thing
    temp = (uint8_t *)malloc(size);
    if (temp == NULL)
        goto err;
    // pack data
    memcpy(temp + offsetof(struct key_t, cipher), &k->cipher,
           sizeof(k->cipher));
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

// FORMAT: [nonce][ciphertext (padding|data)]
int unbox(const uint8_t *public_key, const uint8_t *secret_key,
          const uint8_t *c, const uint32_t clen, uint8_t **m, uint32_t *mlen) {
    uint8_t *temp = NULL;
    // avoid freeing random data and return m=NULL,mlen=0 on error
    *m = NULL;
    *mlen = 0;
    // ensure clen size is big enough
    if (clen <= crypto_box_NONCEBYTES + crypto_box_ZEROBYTES) {
        goto err;
    }
    // allocate temp array for unboxing
    temp = (uint8_t *)malloc(clen - crypto_box_NONCEBYTES);
    if (temp == NULL)
        goto err;
    // unbox; return 0 on success
    if (crypto_box_open(temp, /*plaintext*/
                        &c[crypto_box_NONCEBYTES],
                        clen - crypto_box_NONCEBYTES, /*ciphertext*/
                        c,                            /*nonce*/
                        public_key, secret_key)) {
        goto err;
    }
    // allocate final output array and remove padding
    *mlen = clen - crypto_box_NONCEBYTES - crypto_box_ZEROBYTES;
    *m = (uint8_t *)malloc(*mlen);
    if (*m == NULL)
        goto err;
    // output data
    memcpy(*m, &temp[crypto_box_ZEROBYTES], *mlen);

    // happy days
    free(temp);
    return 0;
err:
    free(temp);
    return 1;
}

// FORMAT: [nonce][ciphertext (padding|data)]
int box(const uint8_t *public_key, const uint8_t *secret_key,
        const uint8_t *nonce, const uint8_t *m, const uint32_t mlen,
        uint8_t **c, uint32_t *clen) {
    uint8_t *padded = NULL, *out = NULL;
    uint32_t outlen = crypto_box_NONCEBYTES + crypto_box_ZEROBYTES + mlen;
    // avoid freeing random data and return c=NULL,clen=0 on error
    *c = NULL;
    *clen = 0;
    // zero-pad the input
    padded = (uint8_t *)malloc(mlen + crypto_box_ZEROBYTES);
    if (padded == NULL)
        goto err;
    memset(padded, 0, crypto_box_ZEROBYTES);
    memcpy(padded + crypto_box_ZEROBYTES, m, mlen);
    // allocate output array for boxing ([nonce][ciphertext])
    out = (uint8_t *)malloc(outlen);
    // copy nonce
    memcpy(out, nonce, crypto_box_NONCEBYTES);
    // box
    if (crypto_box(&out[crypto_box_NONCEBYTES], padded,
                   mlen + crypto_box_ZEROBYTES, nonce, public_key,
                   secret_key)) {
        goto err;
    }
    // output data
    *c = out;
    *clen = outlen;

    free(padded);
    return 0;
err:
    *c = NULL;
    *clen = 0;
    free(padded);
    free(out);
    return 1;
}