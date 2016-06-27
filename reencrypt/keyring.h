#ifndef __KEYRING_H__
#define __KEYRING_H__

#include "reencrypt_t.h"
#include "types.h"
#include <stdint.h>

/* get a key from id
        input:
                id, key id

        returns:
                pointer to key, if succeed. NULL otherwise
*/
reencrypt_status get_key(const key_id id, struct key_t **key);

/* put a key by id
        input:
                id, key id
                key, data associated with key
*/
// reencrypt_status put_key(const key_id id, const struct key_t *key);
reencrypt_status put_key(const struct key_t *key, key_id id);

/* serialize a key
        input:
                k, pointer to key

        output:
                blob, pointer to pointer to serialized key. allocated inside,
                          needs to be freed
                bloblen, pointer to blob length
*/
reencrypt_status key_serialize(const struct key_t *k, uint8_t **blob,
                               size_t *bloblen);

/* deserialize a key
        input:
                blob, pointer to serialized key
                bloblen, pointer to blob length

        output:
                k, pointer to pointer to key. allocated inside, needs to be
   freed
*/
reencrypt_status key_deserialize(struct key_t **k, const uint8_t *blob,
                                 const size_t bloblen);

/* frees allocated memory */
void key_free(struct key_t *k);

#endif