#include "request.h"

// FORMAT: [keyIDin][keyIDout][ciphertext]
reencrypt_status unpack_request(const uint8_t *request, const size_t requestlen,
                                key_id *keyIDin, key_id *keyIDout, uint8_t **c,
                                size_t *clen) {
    // avoid freeing random data
    *c = NULL;
    *clen = 0;
    // ensure clen size is big enough (at least two key_ids + non-empty c)
    if (requestlen <= 2 * sizeof(key_id)) {
        goto err;
    }
    // extract key_ids
    memcpy(keyIDin, request, sizeof(key_id));
    memcpy(keyIDout, &request[sizeof(key_id)], sizeof(key_id));
    // assign the remaining data as the ciphertext
    *clen = requestlen - 2 * sizeof(key_id);
    *c = (uint8_t *)malloc(*clen);
    if (*c == NULL)
        goto err;
    memcpy(*c, &request[2 * sizeof(key_id)], *clen);

    return REENCRYPT_OK;
err:
    *c = NULL;
    *clen = 0;
    return REENCRYPT_FAILED;
}
