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
reencrypt_status get_key(const key_id id, struct keydata_t **key);

/* put a key by id
        input:
                id, key id
                key, data associated with key
*/
// reencrypt_status put_key(const key_id id, const struct keydata_t *key);
reencrypt_status put_key(const struct keydata_t *key, key_id id);

/* frees allocated memory */
void key_free(struct keydata_t *k);

#endif
