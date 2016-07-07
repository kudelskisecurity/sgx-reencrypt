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
    uint8_t *temp = NULL;
	size_t size;

	// calculate required size for serialized array
	size = sizeof(struct keydata_t) +
		(k->n_keys_from + k->n_keys_to) * sizeof(key_id) +
		k->n_authorized_clients * sizeof(client_id);

	// allocate enough memory for this thing
    temp = malloc(size);
    if (temp == NULL)
        goto err;
	// copy all the values except the dynamic arrays
	memcpy(temp, k, offsetof(struct keydata_t, keys_from));
	// copy the dynamic arrays
	memcpy(temp + offsetof(struct keydata_t, keys_from),
		k->keys_from,
		k->n_keys_from * sizeof(key_id));
	memcpy(temp + offsetof(struct keydata_t, keys_from) +
		k->n_keys_from * sizeof(key_id),
		k->keys_to,
		k->n_keys_to * sizeof(key_id));
	memcpy(temp + offsetof(struct keydata_t, keys_from) +
		(k->n_keys_from + k->n_keys_to) * sizeof(key_id),
		k->authorized_clients,
		k->n_authorized_clients * sizeof(client_id));

    // output blob and size
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
	struct keydata_t *temp = NULL;
	// check the blob is long enough to store the required values
	if(bloblen < offsetof(struct keydata_t, keys_from)) {
		goto err;
	}
	// allocate memory for the output object
	temp = malloc(sizeof(struct keydata_t));
	if(temp == NULL) {
		goto err;
	}
	// zero the structure to avoid freeing random pointers on error
	memset(temp, 0, sizeof(struct keydata_t));
	// copy everything but the dynamic arrays
	memcpy(temp, blob, offsetof(struct keydata_t, keys_from));
	// TODO: check the blob is long enough to store the dynamic arrays
	if(0) {
		goto err;
	}
	// allocate space for the dynamic arrays
	temp->keys_from = malloc(temp->n_keys_from * sizeof(key_id));
	if(temp->keys_from == NULL) {
		goto err;
	}
	temp->keys_to = malloc(temp->n_keys_to * sizeof(key_id));
	if(temp->keys_to == NULL) {
		goto err;
	}
	temp->authorized_clients = malloc(temp->n_authorized_clients *
		sizeof(client_id));
	if(temp->authorized_clients == NULL) {
		goto err;
	}
	// copy the dynamic arrays
	memcpy(temp->keys_from, blob + offsetof(struct keydata_t, keys_from),
		temp->n_keys_from * sizeof(key_id));
	memcpy(temp->keys_to, blob + offsetof(struct keydata_t, keys_from) +
		temp->n_keys_from * sizeof(key_id),
		temp->n_keys_to * sizeof(key_id));
	memcpy(temp->authorized_clients, blob +
		offsetof(struct keydata_t, keys_from) +
		(temp->n_keys_from + temp->n_keys_to) * sizeof(key_id),
		temp->n_authorized_clients * sizeof(client_id));

	// output the key
	*k = temp;
	return REENCRYPT_OK;
err:
	if(temp != NULL) {
		free(temp->keys_from);
		free(temp->keys_to);
		free(temp->authorized_clients);
	}
	free(temp);
	return REENCRYPT_FAILED;
}
