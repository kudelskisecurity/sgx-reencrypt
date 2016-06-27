#include "aes128gcm.h"
#include "sgx_tcrypto.h"
#include "sgx_trts.h"
#include <string.h>

// space needed to store the ciphertext:
//  - 
size_t aes128gcm_ciphertext_size(const size_t plainlen)
{
	return SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE + plainlen;
}

size_t aes128gcm_plaintext_size(const size_t cipherlen)
{
	return cipherlen - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE;
}

uint32_t aes128gcm_decrypt(const uint8_t *key, const size_t keylen, 
						   const uint8_t *bufin, const size_t bufinlen,
						   uint8_t *bufout, size_t bufoutlen)
{
	size_t ciphertextlen = bufinlen - (SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE);
	// check keylen and buffer bounds
	if(keylen != 16 || bufoutlen < aes128gcm_plaintext_size(bufinlen))
	{
		return 0Xffffffff;
	}
	// decrypt
	if(SGX_SUCCESS != sgx_rijndael128GCM_decrypt((sgx_aes_ctr_128bit_key_t*) key,
		bufin + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE, ciphertextlen, // ciphertext
		bufout, // plaintext
		bufin, SGX_AESGCM_IV_SIZE, // IV
		NULL, 0, // aad
		(sgx_aes_gcm_128bit_tag_t*) (bufin + SGX_AESGCM_IV_SIZE)
		))
	{
		return 0xffffffff;
	}
	return 0;
}

uint32_t aes128gcm_encrypt(const uint8_t *key, const size_t keylen, 
						   const uint8_t *bufin, const size_t bufinlen,
						   uint8_t *bufout, size_t bufoutlen)
{
	// check keylen and buffer bounds
	if(keylen != 16 || bufoutlen < aes128gcm_ciphertext_size(bufinlen))
	{
		return 0Xffffffff;
	}
	// source random IV from rdrand
	if(sgx_read_rand(bufout, SGX_AESGCM_IV_SIZE) != SGX_SUCCESS)
	{
		return 0Xffffffff;
	}
	// encrypt
	if(SGX_SUCCESS != sgx_rijndael128GCM_encrypt((sgx_aes_ctr_128bit_key_t*) key,
		bufin, bufinlen, // plaintext
		bufout + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE, // ciphertext
		bufout, SGX_AESGCM_IV_SIZE, // iv
		NULL, 0, // aad
		(sgx_aes_gcm_128bit_tag_t*) (bufout + SGX_AESGCM_IV_SIZE) // mac
		))
	{
		return 0Xffffffff;
	}

	return 0;
}
