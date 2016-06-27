#include "sealing.h"
#include "sgx_tseal.h"
#include "types.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* seal an array

        return:
                ???

        input:
                plain, array containing data to be sealed
                plainlen, lenght of plain array
        output:
                sealed, pointer to pointer to sealed array. allocated inside
                sealedlen, length of sealed array

*/
reencrypt_status seal(const uint8_t *aad, const size_t aadlen,
                      const uint8_t *plain, const size_t plainlen,
                      uint8_t **sealed, size_t *sealedlen) {
    size_t templen;
    uint8_t *temp = NULL;
    // calculate required space for sealed blob
    if ((templen = sgx_calc_sealed_data_size(aadlen, plainlen)) == 0xFFFFFFFF) {
        return REENCRYPT_SEALING_FAILED;
    }
    // allocate memory for output buffer
    temp = (uint8_t *)malloc(templen);
    if (temp == NULL)
        goto err;
    // seal input
    if (sgx_seal_data(aadlen, aad, plainlen, plain, templen,
                      (sgx_sealed_data_t *)temp) != SGX_SUCCESS) {
        goto err;
    }

    // output data
    *sealed = temp;
    *sealedlen = templen;
    return REENCRYPT_OK;
err:
    free(temp);
    *sealed = NULL;
    *sealedlen = 0;
    return REENCRYPT_FAILED;
}

/* unseal an array

        return:
                ???

        input:
                sealed, array containing data to be unsealed
                sealedlen, lenght of sealed array
        output:
                plain, pointer to pointer to plain array. allocated inside
                plainlen, length of plain array

*/
reencrypt_status unseal(const uint8_t *sealed, const size_t sealedlen,
                        uint8_t **aad, size_t *aadlen, uint8_t **plain,
                        size_t *plainlen) {
    uint32_t outlen, tempaadlen /*needed for unsealing*/;
    uint8_t *tempout = NULL, *tempaad = NULL, *tempin = NULL;
    // copy buffer; sealed data must be inside enclave
    tempin = (uint8_t *)malloc(sealedlen);
    if (tempin == NULL)
        goto err;
    memcpy(tempin, sealed, sealedlen);
    // calculate required space for aad data
    if ((tempaadlen = sgx_get_add_mac_txt_len((sgx_sealed_data_t *)sealed)) ==
        0xFFFFFFFF) {
        goto err;
    }
    // calculate required space for unsealed data
    if ((outlen = sgx_get_encrypt_txt_len((sgx_sealed_data_t *)sealed)) ==
        0xFFFFFFFF) {
        goto err;
    }
    // allocate memory
    tempaad = (uint8_t *)malloc(tempaadlen);
    if (tempaad == NULL)
        goto err;
    tempout = (uint8_t *)malloc(outlen);
    if (tempout == NULL)
        goto err;
    // unseal data
    if (sgx_unseal_data((sgx_sealed_data_t *)tempin, tempaad, &tempaadlen,
                        tempout, &outlen) != SGX_SUCCESS) {
        goto err;
    }
    // output data
    *plain = tempout;
    *plainlen = outlen;
    *aad = tempaad;
    *aadlen = tempaadlen;
    free(tempin);
    return REENCRYPT_OK;
err:
    free(tempin);
    free(tempaad);
    free(tempout);
    return REENCRYPT_FAILED;
}