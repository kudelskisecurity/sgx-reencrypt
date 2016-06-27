#include "types.h"
#include <stdint.h>

reencrypt_status key_serialize(const struct key_t *k, uint8_t **blob,
                               uint32_t *bloblen);
// FORMAT: [nonce][ciphertext (padding|data)]
int box(const uint8_t *public_key, const uint8_t *secret_key,
        const uint8_t *nonce, const uint8_t *m, const uint32_t mlen,
        uint8_t **c, uint32_t *clen);

// FORMAT: [nonce][ciphertext (padding|data)]
int unbox(const uint8_t *public_key, const uint8_t *secret_key,
          const uint8_t *c, const uint32_t clen, uint8_t **m, uint32_t *mlen);
