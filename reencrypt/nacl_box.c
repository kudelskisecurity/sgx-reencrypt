#include "nacl_box.h"
#include "tweetnacl/tweetnacl.h"
#include <stdlib.h>
#include <string.h>

// FORMAT: [nonce][ciphertext (padding|data)]
reencrypt_status unbox(const uint8_t *public_key, const uint8_t *secret_key,
                       const uint8_t *c, const size_t clen, uint8_t **m,
                       size_t *mlen) {
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
    return REENCRYPT_OK;
err:
    free(temp);
    return REENCRYPT_FAILED;
}

// FORMAT: [nonce][ciphertext (padding|data)]
reencrypt_status box(const uint8_t *public_key, const uint8_t *secret_key,
                     const uint8_t nonce[crypto_box_NONCEBYTES],
                     const uint8_t *m, const size_t mlen, uint8_t **c,
                     size_t *clen) {
    uint8_t *padded = NULL, *out = NULL;
    size_t outlen = crypto_box_NONCEBYTES + crypto_box_ZEROBYTES + mlen;
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
    return REENCRYPT_OK;
err:
    *c = NULL;
    *clen = 0;
    free(padded);
    free(out);
    return REENCRYPT_FAILED;
}