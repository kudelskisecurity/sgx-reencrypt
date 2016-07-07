#ifndef REENCRYPT_T_H__
#define REENCRYPT_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "types.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


int generate_keypair(uint8_t* public_key);
int seal_keypair();
int unseal_keypair(uint8_t* public_key);
int reencrypt(client_id* clid, uint8_t* request, size_t requestlen, uint8_t* response, size_t* responselen);
int register_key(client_id* clid, uint8_t* request, size_t requestlen, uint8_t* response, size_t* responselen);

sgx_status_t SGX_CDECL untrusted_fs_store(int* retval, char* name, size_t namelen, uint8_t* data, size_t datalen);
sgx_status_t SGX_CDECL untrusted_fs_load(int* retval, char* name, size_t namelen, uint8_t** data, size_t* datalen);
sgx_status_t SGX_CDECL untrusted_fs_free(uint8_t* data);
sgx_status_t SGX_CDECL time(uint64_t* retval, uint64_t* timer);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
