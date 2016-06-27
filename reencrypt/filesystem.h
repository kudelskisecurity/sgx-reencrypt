#pragma once

#include "reencrypt_t.h"
#include "sgx_trts.h"
#include "types.h"
#include <stdint.h>

reencrypt_status fs_store(char *name, size_t namelen, uint8_t *data,
                          size_t datalen);
reencrypt_status fs_load(char *name, size_t namelen, uint8_t **data,
                         size_t *datalen);
reencrypt_status fs_free(uint8_t *data);

