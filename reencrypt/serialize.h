#pragma once
#include "types.h"
#include <stdint.h>

/* serialize a key
        input:
                k, pointer to key

        output:
                blob, pointer to pointer to serialized key. allocated inside,
                          needs to be freed
                bloblen, pointer to blob length
*/
reencrypt_status key_serialize(const struct keydata_t *k, uint8_t **blob,
                               size_t *bloblen);

/* deserialize a key
        input:
                blob, pointer to serialized key
                bloblen, pointer to blob length

        output:
                k, pointer to pointer to key. allocated inside, needs to be
   freed
*/
reencrypt_status key_deserialize(struct keydata_t **k, const uint8_t *blob,
                                 const size_t bloblen);
