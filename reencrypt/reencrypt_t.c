#include "reencrypt_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */

#include <string.h> /* for memcpy etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

/* sgx_ocfree() just restores the original outside stack pointer. */
#define OCALLOC(val, type, len) do {	\
	void* __tmp = sgx_ocalloc(len);	\
	if (__tmp == NULL) {	\
		sgx_ocfree();	\
		return SGX_ERROR_UNEXPECTED;\
	}			\
	(val) = (type)__tmp;	\
} while (0)


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

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4127)
#pragma warning(disable: 4200)
#endif

static sgx_status_t SGX_CDECL sgx_generate_keypair(void* pms)
{
	ms_generate_keypair_t* ms = SGX_CAST(ms_generate_keypair_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_public_key = ms->ms_public_key;
	size_t _len_public_key = 32;
	uint8_t* _in_public_key = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_generate_keypair_t));
	CHECK_UNIQUE_POINTER(_tmp_public_key, _len_public_key);

	if (_tmp_public_key != NULL) {
		if ((_in_public_key = (uint8_t*)malloc(_len_public_key)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_public_key, 0, _len_public_key);
	}
	ms->ms_retval = generate_keypair(_in_public_key);
err:
	if (_in_public_key) {
		memcpy(_tmp_public_key, _in_public_key, _len_public_key);
		free(_in_public_key);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_seal_keypair(void* pms)
{
	ms_seal_keypair_t* ms = SGX_CAST(ms_seal_keypair_t*, pms);
	sgx_status_t status = SGX_SUCCESS;

	CHECK_REF_POINTER(pms, sizeof(ms_seal_keypair_t));

	ms->ms_retval = seal_keypair();


	return status;
}

static sgx_status_t SGX_CDECL sgx_unseal_keypair(void* pms)
{
	ms_unseal_keypair_t* ms = SGX_CAST(ms_unseal_keypair_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_public_key = ms->ms_public_key;
	size_t _len_public_key = 32;
	uint8_t* _in_public_key = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_unseal_keypair_t));
	CHECK_UNIQUE_POINTER(_tmp_public_key, _len_public_key);

	if (_tmp_public_key != NULL) {
		if ((_in_public_key = (uint8_t*)malloc(_len_public_key)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_public_key, 0, _len_public_key);
	}
	ms->ms_retval = unseal_keypair(_in_public_key);
err:
	if (_in_public_key) {
		memcpy(_tmp_public_key, _in_public_key, _len_public_key);
		free(_in_public_key);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_reencrypt(void* pms)
{
	ms_reencrypt_t* ms = SGX_CAST(ms_reencrypt_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	client_id* _tmp_clid = ms->ms_clid;
	uint8_t* _tmp_request = ms->ms_request;
	uint8_t* _tmp_response = ms->ms_response;
	size_t* _tmp_responselen = ms->ms_responselen;

	CHECK_REF_POINTER(pms, sizeof(ms_reencrypt_t));

	ms->ms_retval = reencrypt(_tmp_clid, _tmp_request, ms->ms_requestlen, _tmp_response, _tmp_responselen);


	return status;
}

static sgx_status_t SGX_CDECL sgx_register_key(void* pms)
{
	ms_register_key_t* ms = SGX_CAST(ms_register_key_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	client_id* _tmp_clid = ms->ms_clid;
	uint8_t* _tmp_request = ms->ms_request;
	uint8_t* _tmp_response = ms->ms_response;
	size_t* _tmp_responselen = ms->ms_responselen;

	CHECK_REF_POINTER(pms, sizeof(ms_register_key_t));

	ms->ms_retval = register_key(_tmp_clid, _tmp_request, ms->ms_requestlen, _tmp_response, _tmp_responselen);


	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* call_addr; uint8_t is_priv;} ecall_table[5];
} g_ecall_table = {
	5,
	{
		{(void*)(uintptr_t)sgx_generate_keypair, 0},
		{(void*)(uintptr_t)sgx_seal_keypair, 0},
		{(void*)(uintptr_t)sgx_unseal_keypair, 0},
		{(void*)(uintptr_t)sgx_reencrypt, 0},
		{(void*)(uintptr_t)sgx_register_key, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[4][5];
} g_dyn_entry_table = {
	4,
	{
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL untrusted_fs_store(int* retval, char* name, size_t namelen, uint8_t* data, size_t datalen)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_name = namelen;
	size_t _len_data = datalen;

	ms_untrusted_fs_store_t* ms;
	OCALLOC(ms, ms_untrusted_fs_store_t*, sizeof(*ms));

	if (name != NULL && sgx_is_within_enclave(name, _len_name)) {
		OCALLOC(ms->ms_name, char*, _len_name);
		memcpy(ms->ms_name, name, _len_name);
	} else if (name == NULL) {
		ms->ms_name = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_namelen = namelen;
	if (data != NULL && sgx_is_within_enclave(data, _len_data)) {
		OCALLOC(ms->ms_data, uint8_t*, _len_data);
		memcpy(ms->ms_data, data, _len_data);
	} else if (data == NULL) {
		ms->ms_data = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_datalen = datalen;
	status = sgx_ocall(0, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL untrusted_fs_load(int* retval, char* name, size_t namelen, uint8_t** data, size_t* datalen)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_name = namelen;
	size_t _len_data = sizeof(*data);
	size_t _len_datalen = sizeof(*datalen);

	ms_untrusted_fs_load_t* ms;
	OCALLOC(ms, ms_untrusted_fs_load_t*, sizeof(*ms));

	if (name != NULL && sgx_is_within_enclave(name, _len_name)) {
		OCALLOC(ms->ms_name, char*, _len_name);
		memcpy(ms->ms_name, name, _len_name);
	} else if (name == NULL) {
		ms->ms_name = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_namelen = namelen;
	if (data != NULL && sgx_is_within_enclave(data, _len_data)) {
		OCALLOC(ms->ms_data, uint8_t**, _len_data);
		memset(ms->ms_data, 0, _len_data);
	} else if (data == NULL) {
		ms->ms_data = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (datalen != NULL && sgx_is_within_enclave(datalen, _len_datalen)) {
		OCALLOC(ms->ms_datalen, size_t*, _len_datalen);
		memset(ms->ms_datalen, 0, _len_datalen);
	} else if (datalen == NULL) {
		ms->ms_datalen = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(1, ms);

	if (retval) *retval = ms->ms_retval;
	if (data) memcpy((void*)data, ms->ms_data, _len_data);
	if (datalen) memcpy((void*)datalen, ms->ms_datalen, _len_datalen);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL untrusted_fs_free(uint8_t* data)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_untrusted_fs_free_t* ms;
	OCALLOC(ms, ms_untrusted_fs_free_t*, sizeof(*ms));

	ms->ms_data = SGX_CAST(uint8_t*, data);
	status = sgx_ocall(2, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL time(uint64_t* retval, uint64_t* timer)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_time_t* ms;
	OCALLOC(ms, ms_time_t*, sizeof(*ms));

	ms->ms_timer = SGX_CAST(uint64_t*, timer);
	status = sgx_ocall(3, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif
