#include "reencrypt_u.h"

typedef struct ms_generate_keypair_t {
	int ms_retval;
	uint8_t* ms_public_key;
} ms_generate_keypair_t;

typedef struct ms_seal_keypair_t {
	int ms_retval;
} ms_seal_keypair_t;

typedef struct ms_unseal_keypair_t {
	int ms_retval;
	uint8_t* ms_public_key;
} ms_unseal_keypair_t;

typedef struct ms_reencrypt_t {
	int ms_retval;
	client_id* ms_clid;
	uint8_t* ms_request;
	size_t ms_requestlen;
	uint8_t* ms_response;
	size_t* ms_responselen;
} ms_reencrypt_t;

typedef struct ms_register_key_t {
	int ms_retval;
	client_id* ms_clid;
	uint8_t* ms_request;
	size_t ms_requestlen;
	uint8_t* ms_response;
	size_t* ms_responselen;
} ms_register_key_t;

typedef struct ms_untrusted_fs_store_t {
	int ms_retval;
	char* ms_name;
	size_t ms_namelen;
	uint8_t* ms_data;
	size_t ms_datalen;
} ms_untrusted_fs_store_t;

typedef struct ms_untrusted_fs_load_t {
	int ms_retval;
	char* ms_name;
	size_t ms_namelen;
	uint8_t** ms_data;
	size_t* ms_datalen;
} ms_untrusted_fs_load_t;

typedef struct ms_untrusted_fs_free_t {
	uint8_t* ms_data;
} ms_untrusted_fs_free_t;

typedef struct ms_time_t {
	uint64_t ms_retval;
	uint64_t* ms_timer;
} ms_time_t;

static sgx_status_t SGX_CDECL reencrypt_untrusted_fs_store(void* pms)
{
	ms_untrusted_fs_store_t* ms = SGX_CAST(ms_untrusted_fs_store_t*, pms);
	ms->ms_retval = untrusted_fs_store(ms->ms_name, ms->ms_namelen, ms->ms_data, ms->ms_datalen);
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL reencrypt_untrusted_fs_load(void* pms)
{
	ms_untrusted_fs_load_t* ms = SGX_CAST(ms_untrusted_fs_load_t*, pms);
	ms->ms_retval = untrusted_fs_load(ms->ms_name, ms->ms_namelen, ms->ms_data, ms->ms_datalen);
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL reencrypt_untrusted_fs_free(void* pms)
{
	ms_untrusted_fs_free_t* ms = SGX_CAST(ms_untrusted_fs_free_t*, pms);
	untrusted_fs_free(ms->ms_data);
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL reencrypt_time(void* pms)
{
	ms_time_t* ms = SGX_CAST(ms_time_t*, pms);
	ms->ms_retval = time(ms->ms_timer);
	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * func_addr[4];
} ocall_table_reencrypt = {
	4,
	{
		(void*)(uintptr_t)reencrypt_untrusted_fs_store,
		(void*)(uintptr_t)reencrypt_untrusted_fs_load,
		(void*)(uintptr_t)reencrypt_untrusted_fs_free,
		(void*)(uintptr_t)reencrypt_time,
	}
};

sgx_status_t generate_keypair(sgx_enclave_id_t eid, int* retval, uint8_t* public_key)
{
	sgx_status_t status;
	ms_generate_keypair_t ms;
	ms.ms_public_key = public_key;
	status = sgx_ecall(eid, 0, &ocall_table_reencrypt, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t seal_keypair(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_seal_keypair_t ms;
	status = sgx_ecall(eid, 1, &ocall_table_reencrypt, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t unseal_keypair(sgx_enclave_id_t eid, int* retval, uint8_t* public_key)
{
	sgx_status_t status;
	ms_unseal_keypair_t ms;
	ms.ms_public_key = public_key;
	status = sgx_ecall(eid, 2, &ocall_table_reencrypt, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t reencrypt(sgx_enclave_id_t eid, int* retval, client_id* clid, uint8_t* request, size_t requestlen, uint8_t* response, size_t* responselen)
{
	sgx_status_t status;
	ms_reencrypt_t ms;
	ms.ms_clid = clid;
	ms.ms_request = request;
	ms.ms_requestlen = requestlen;
	ms.ms_response = response;
	ms.ms_responselen = responselen;
	status = sgx_ecall(eid, 3, &ocall_table_reencrypt, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t register_key(sgx_enclave_id_t eid, int* retval, client_id* clid, uint8_t* request, size_t requestlen, uint8_t* response, size_t* responselen)
{
	sgx_status_t status;
	ms_register_key_t ms;
	ms.ms_clid = clid;
	ms.ms_request = request;
	ms.ms_requestlen = requestlen;
	ms.ms_response = response;
	ms.ms_responselen = responselen;
	status = sgx_ecall(eid, 4, &ocall_table_reencrypt, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

