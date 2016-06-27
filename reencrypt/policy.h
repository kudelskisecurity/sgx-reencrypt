#pragma once

#include "keyring.h"
#include "types.h"
#include <stdint.h>
#include <string.h>

/* check a policy

        return:
                policy_status, POLICY_OK if valid; different otherwise

        input:
                clid, pointer to the client_id performing the action
                key_from, key_id identifying the key encrypting from
                key_to, key_id identifying the key encrypting to
        output:
                keyin, key referenced by keyIDin, if valid. NULL otherwise
                keyin, key referenced by keyIDout, if valid. NULL otherwise

*/
reencrypt_status check_policy(struct key_t **keyin, struct key_t **keyout,
                              const client_id *clid, const key_id key_from,
                              const key_id key_to);

/* serialize a policy
        input:
                p, pointer to policy

        output:
                blob, pointer to pointer to serialized policy. allocated inside,
                          needs to be freed
                bloblen, pointer to blob length
*/

