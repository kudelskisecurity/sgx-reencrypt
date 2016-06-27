# SGX-reencrypt 

**Disclaimer**: This is a PoC of an SGX-based application, but is
insecure as it is. To build secure SGX-based applications, you'll need
to perform the remote attestation step after being approved as an SGX
license.


SGX-reencrypt is an SGX-based application that performs symmetric-key
*proxy reencryption*: SGX-reencrypt runs as a service that receives
encrypted requests containing

* A nonce `N` unique for this request

* A ciphertext `C` encrypted and authenticated with key with key id  `i`

* The key id `i` of the original ciphertext

* A key id `j` for the new ciphertext

The SGX-reencrypt service then

1. Decrypts and verifies the request
2. Verifies that the policy allows to reencrypt from key id `i` to key id
`j`. Upon failure, returns `N || 0x01 || C`
3. Decrypt and verifies the ciphertext `C` using key with key
id `i`, returning a plaintext `P`. Upon failure, returns `N || 0x02 || C` 
4. Encrypt and authenticate `P` using key id `j` to get a ciphertext
`C0`, returns `N || 0x00 || C0`

Requests are encrypted using the `crypto_box()` function from TweetNaCl
(public-key authenticated encryption).  Plaintexts are encrypted using
AES-GCM.

This assumes that keys and a policy have been sealed to the reencrypt
enclave, as well as the enclave's Curve25519 private key.


## API

Trusted functions (ecalls):
```
/* generate channel keypair */
public int generate_keypair([out, size=32] uint8_t *public_key);
/* seal/unseal channel keypair */
public int seal_keypair();
public int unseal_keypair([out, size=32] uint8_t *public_key);

/* reencryption */
public int reencrypt([user_check]client_id *clid,
        [user_check]uint8_t *request, size_t requestlen,
        [user_check]uint8_t *response,
        [user_check]size_t *responselen);

/* key registration
        input:
                - client id
                - boxed serialized key

        output:
                - boxed key id
*/
public int register_key([user_check] client_id *clid,
        [user_check]uint8_t *request, size_t requestlen,
        [user_check]uint8_t *response,
        [user_check]size_t *responselen);
```

Untrusted functions (ocalls):

```

// filesystem functions. return 0 if success, 1 otherwise
int untrusted_fs_store([in, size=namelen] char *name, size_t namelen, [in, size=datalen] uint8_t *data, size_t datalen);
int untrusted_fs_load([in, size=namelen] char *name, size_t namelen, [out] uint8_t **data, [out] size_t *datalen);
void untrusted_fs_free([user_check] uint8_t *data);
// unsafe time
uint64_t time([user_check] uint64_t *timer);
```




## Security

1. Provisioned keys will only be exposed during provisioning. If the system is
   compromised at the moment of key provisioning, keys can be intercepted.
   After provisioning, keys will only remain in plaintext inside an enclave,
   and its security depends on the assumption that SGX is secure.

2. Reencrypted plaintext will only be handled inside an enclave. Its
   security depends on the assumption that SGX is secure and the assumption
   that input and output keys has not been compromised.

3. Reencryption requests hide the ciphertext and key ids, and responses
   attempt to make errors indistinguishable from successes.

3. Reencryption leaks the approximate plaintext length.

4. The API provides no security on protecting the plaintext: as
   the `register_key()` function is exposed publicly, a privileged
   adversary can register an arbitrary key under her control, intercept
   ciphertexts during reencrypt() invokation and invoke again with the
   intercepted ciphertext and the `key_id` under her control.

5. `register_key()` is not thread-safe.
