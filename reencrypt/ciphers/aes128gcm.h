#ifndef _AES128GCM_H_
#define _AES128GCM_H_
#include <sgx_tcrypto.h>
#include <stdint.h>
#include <stdlib.h>


size_t aes128gcm_ciphertext_size(const size_t plainlen);
size_t aes128gcm_plaintext_size(const size_t cipherlen);
uint32_t aes128gcm_encrypt(const sgx_aes_gcm_128bit_key_t *key,
    const uint8_t *bufin, const size_t bufinlen, uint8_t *bufout, size_t bufoutlen);
uint32_t aes128gcm_decrypt(const sgx_aes_gcm_128bit_key_t *key,
    const uint8_t *bufin, const size_t bufinlen, uint8_t *bufout, size_t bufoutlen);

#endif
