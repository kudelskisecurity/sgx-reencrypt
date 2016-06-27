#include "unsafe_clock.h"
#include "reencrypt_t.h"

reencrypt_status unsafe_timestamp(uint64_t *ts) {
    uint64_t ret;
    ret = time(ts, NULL);
    return (ret == SGX_SUCCESS ? REENCRYPT_OK : REENCRYPT_FAILED);
}
