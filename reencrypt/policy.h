#pragma once

#include "keyring.h"
#include "types.h"
#include <stdint.h>
#include <string.h>

/* check a policy

        return:
                policy_status, POLICY_OK if valid; different otherwise

        input:
                clid, client_id performing the action
                key_from, key_id identifying the key encrypting from
                keydata_to, key_id identifying the key encrypting to
        output:
                keyin, key referenced by keyIDin, if valid. NULL otherwise
                keyin, key referenced by keyIDout, if valid. NULL otherwise

*/
reencrypt_status check_policy(struct keydata_t **keyin, struct keydata_t **keyout,
                              const client_id clid, const key_id key_from,
                              const key_id keydata_to);

