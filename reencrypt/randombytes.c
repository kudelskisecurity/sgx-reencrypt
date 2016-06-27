#include "sgx_trts.h"

// for tweetnacl
// void randombytes(u8 *,u64)
// this can cause a denial of service entering an infinite loop
// in case sgx_read_rand is not able to return successfully.
// given this function is used as part of tweetnacl, and a behaviour
// different than sourcing random bytes might compromise security,
// this side effect is acceptable at this point.
int randombytes(unsigned char *b, unsigned long long n) {
    sgx_status_t status;
    status = sgx_read_rand(b, n);
    return (status == SGX_SUCCESS ? 0 : 1);
}
