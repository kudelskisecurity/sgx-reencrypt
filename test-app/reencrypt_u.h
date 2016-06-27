#ifndef REENCRYPT_U_H__
#define REENCRYPT_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "types.h"

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

int SGX_UBRIDGE(SGX_NOCONVENTION, untrusted_fs_store, (char* name, size_t namelen, uint8_t* data, size_t datalen));
int SGX_UBRIDGE(SGX_NOCONVENTION, untrusted_fs_load, (char* name, size_t namelen, uint8_t** data, size_t* datalen));
void SGX_UBRIDGE(SGX_NOCONVENTION, untrusted_fs_free, (uint8_t* data));
uint64_t SGX_UBRIDGE(SGX_NOCONVENTION, time, (uint64_t* timer));

sgx_status_t generate_keypair(sgx_enclave_id_t eid, int* retval, uint8_t* public_key);
sgx_status_t seal_keypair(sgx_enclave_id_t eid, int* retval);
sgx_status_t unseal_keypair(sgx_enclave_id_t eid, int* retval, uint8_t* public_key);
sgx_status_t reencrypt(sgx_enclave_id_t eid, int* retval, client_id* clid, uint8_t* request, size_t requestlen, uint8_t* response, size_t* responselen);
sgx_status_t register_key(sgx_enclave_id_t eid, int* retval, client_id* clid, uint8_t* request, size_t requestlen, uint8_t* response, size_t* responselen);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
