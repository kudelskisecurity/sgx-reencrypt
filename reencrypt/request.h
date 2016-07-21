#pragma once

#include "types.h"
#include <stdlib.h>
#include <string.h>

/* packs a request into a data array

        return:
                reencrypt_status, REENCRYPT_OK if succeeded; different otherwise

        input:
                keyIDin, keyIDout, key_id input and output for reencryption
                c, data array containing the ciphertext to be reencrypted
                clen, c length
        output:
                request, pointer the data array containing the request.
                        allocated inside; needs to be freed.
                requestlen, request length

*/
reencrypt_status pack_request(const key_id keyIDin, const key_id keyIDout,
                              const uint8_t *c, const size_t *clen,
                              uint8_t **request, size_t *requestlen);

/* unpacks a request from a data array

        return:
                reencrypt_status, REENCRYPT_OK if succeeded; different otherwise

        input:
                request, data array containing the packed request
                requestlen, request length
        output:
                keyIDin, keyIDout, pointer to key_id input and output for
   reencryption.
                c, pointer to data array containing the ciphertext to be
   reencrypted.
                        allocated inside; needs to be freed.
                clen, pointer to c length

*/
reencrypt_status unpack_request(const uint8_t *request, const size_t requestlen,
                                key_id *keyIDin, key_id *keyIDout, uint8_t **c,
                                size_t *clen);
