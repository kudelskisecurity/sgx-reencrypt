#include "filesystem.h"

reencrypt_status fs_store(char *name, size_t namelen, uint8_t *data,
                          size_t datalen) {
    int ret;
    if (untrusted_fs_store(&ret, name, namelen, data, datalen) != SGX_SUCCESS) {
        goto err;
    }
    if (ret) {
        goto err;
    }

    return REENCRYPT_OK;
err:
    return REENCRYPT_FAILED;
}

reencrypt_status fs_load(char *name, size_t namelen, uint8_t **data,
                         size_t *datalen) {
    int ret;
    uint8_t *temp;
    size_t templen;
    if (untrusted_fs_load(&ret, name, namelen, &temp, &templen) !=
        SGX_SUCCESS) {
        goto err;
    }
    if (ret) {
        goto err;
    }
    // no tricks - check the provided pointer is out of the enclave
    if (!sgx_is_outside_enclave(temp, templen)) {
        goto err;
    }
    // ok, output data
    *data = temp;
    *datalen = templen;
    return REENCRYPT_OK;
err:
    return REENCRYPT_FAILED;
}

reencrypt_status fs_free(uint8_t *data) {
    if (untrusted_fs_free(data) != SGX_SUCCESS) {
        return REENCRYPT_FAILED;
    }
    return REENCRYPT_OK;
}
