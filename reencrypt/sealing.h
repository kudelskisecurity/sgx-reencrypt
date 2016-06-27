#pragma once

#include "types.h"
#include <stdint.h>

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
                      uint8_t **sealed, size_t *sealedlen);

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
                        size_t *plainlen);

