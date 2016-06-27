#ifndef __NACLBOX_H__
#define __NACLBOX_H__

#include "tweetnacl/tweetnacl.h"
#include "types.h"

// FORMAT: [nonce][ciphertext (padding|data)]
reencrypt_status box(const uint8_t *public_key, const uint8_t *secret_key,
                     const uint8_t nonce[crypto_box_NONCEBYTES],
                     const uint8_t *m, const size_t mlen, uint8_t **c,
                     size_t *clen);

// FORMAT: [nonce][ciphertext (padding|data)]
reencrypt_status unbox(const uint8_t *public_key, const uint8_t *secret_key,
                       const uint8_t *c, const size_t clen, uint8_t **m,
                       size_t *mlen);

#endif