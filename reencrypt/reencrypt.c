#include "reencrypt_t.h"
#include "reencrypt.h"
#include "serialize.h"


#define KEYPAIR_NAME "keypair.seal"

// global context
static struct reencrypt_context ctx;
static sgx_spinlock_t ctxlock = SGX_SPINLOCK_INITIALIZER;

static reencrypt_status
set_keypair(unsigned char pk[crypto_box_PUBLICKEYBYTES],
            unsigned char sk[crypto_box_SECRETKEYBYTES]) {
    reencrypt_status ret;

    // Critical section: do allow only one thread to succeed here!
    sgx_spin_lock(&ctxlock);
    if (ctx.ready) {
        ret = REENCRYPT_ERROR_KEYPAIR_REGENERATION;
        sgx_spin_unlock(&ctxlock);
        return REENCRYPT_FAILED;
    }
    // copy keypair
    memcpy(ctx.pk, pk, sizeof(ctx.pk));
    memcpy(ctx.sk, sk, sizeof(ctx.sk));
    // ready to go
    ctx.ready = 1;

    sgx_spin_unlock(&ctxlock);
    return REENCRYPT_OK;
}

int generate_keypair(uint8_t *public_key) {
    unsigned char pk[crypto_box_PUBLICKEYBYTES];
    unsigned char sk[crypto_box_SECRETKEYBYTES];
    reencrypt_status ret;

    // generate keypair
    if (crypto_box_keypair(pk, sk)) {
        return REENCRYPT_ERROR_KEYPAIR_REGENERATION;
    }

    if ((ret = set_keypair(pk, sk)) != REENCRYPT_OK) {
        return REENCRYPT_ERROR_KEYPAIR_REGENERATION;
    }
    // output public key
    memcpy(public_key, ctx.pk, sizeof(ctx.pk));

    return REENCRYPT_OK;
}

int seal_keypair() {
    uint8_t *blob = NULL;
    size_t bloblen;
    reencrypt_status ret;

    // only run sealing if keypair has been generated
    if (!ctx.ready) {
        ret = REENCRYPT_NOT_READY;
        goto err;
    }
    // public key will be aad, secret key will be sealed
    if ((ret = seal(ctx.pk, sizeof(ctx.pk), ctx.sk, sizeof(ctx.sk), &blob,
                    &bloblen)) != REENCRYPT_OK) {
        goto err;
    }
    // store it
    if (fs_store(KEYPAIR_NAME, sizeof(KEYPAIR_NAME), blob, bloblen) !=
        REENCRYPT_OK) {
        goto err;
    }

    free(blob);
    return REENCRYPT_OK;
err:
    free(blob);
    return (ret != REENCRYPT_OK ? ret : REENCRYPT_FAILED);
}

int unseal_keypair(uint8_t *public_key) {
    uint8_t *blob = NULL, *pk = NULL, *sk = NULL;
    size_t bloblen, pklen, sklen;
    reencrypt_status ret;

    if (fs_load(KEYPAIR_NAME, sizeof(KEYPAIR_NAME), &blob, &bloblen) !=
        REENCRYPT_OK) {
        goto err;
    }

    if ((ret = unseal(blob, bloblen, &pk, &pklen, &sk, &sklen)) !=
        REENCRYPT_OK) {
        ret = REENCRYPT_SEALING_FAILED;
        goto err;
    }
    // check obtained sizes match the expected
    if (pklen != crypto_box_PUBLICKEYBYTES ||
        sklen != crypto_box_SECRETKEYBYTES) {
        goto err;
    }

    if ((ret = set_keypair(pk, sk)) != REENCRYPT_OK) {
        goto err;
    }
    // output public key
    memcpy(public_key, ctx.pk, sizeof(ctx.pk));
    free(pk);
    free(sk);
    fs_free(blob);
    return REENCRYPT_OK;
err:
    free(pk);
    free(sk);
    fs_free(blob);
    return (ret != REENCRYPT_OK ? ret : REENCRYPT_FAILED);
}

int register_key(client_id *clid, uint8_t *request, size_t requestlen,
                 uint8_t *response, size_t *responselen) {
	uint8_t *s_key = NULL;      // serialized key
    uint8_t *c_response = NULL; // boxed response
    size_t s_keylen;
    size_t c_responselen;
    struct keydata_t *key = NULL;
    key_id kid;
    uint8_t nonce[crypto_box_NONCEBYTES];
    reencrypt_status ret;

    // input checks - everything must be outside of the enclave
    if (!sgx_is_outside_enclave(clid, sizeof(client_id)) ||
        !sgx_is_outside_enclave(request, requestlen) ||
        !sgx_is_outside_enclave(response, *responselen) ||
        !sgx_is_outside_enclave(responselen, sizeof(size_t))) {
        ret = REENCRYPT_INVALID_INPUT;
        goto err;
    }

    if (!ctx.ready) {
        ret = REENCRYPT_NOT_READY;
        goto err;
    }

    if ((ret = unbox((uint8_t *)clid, ctx.sk, request, requestlen, &s_key,
                     &s_keylen)) != REENCRYPT_OK) {
        goto err;
    }

	if ((ret = key_deserialize(&key, s_key, s_keylen)) != REENCRYPT_OK) {
        goto err;
    }

    if ((ret = put_key(key, kid)) != REENCRYPT_OK) {
        goto err;
    }
    // source a random nonce for the response
    {
        if (sgx_read_rand(nonce, crypto_box_NONCEBYTES) != SGX_SUCCESS)
        {
            ret = REENCRYPT_FAILED;
            goto err;
        }
    }
    // output new key id
    if ((ret = box((uint8_t *)clid, ctx.sk, nonce, kid, 16, &c_response,
                   &c_responselen)) != REENCRYPT_OK) {
        goto err;
    }
    // check if we have enough space to output the response
    if (c_responselen > *responselen) {
        ret = REENCRYPT_INCREASE_RESPONSE_SIZE;
        goto err;
    }
    // output response
    memcpy(response, c_response, c_responselen);
    *responselen = c_responselen;

    free(c_response);
    free(s_key);
	free(key);
    return REENCRYPT_OK;
err:
    free(c_response);
    free(s_key);
    free(key);
    return (ret != REENCRYPT_OK ? ret : REENCRYPT_FAILED);
}

/* ENTRY-POINT */
int reencrypt(client_id *clid, uint8_t *request, size_t requestlen,
              uint8_t *response, size_t *responselen) {
    key_id keyIDin, keyIDout;
    struct keydata_t *keyin = NULL, *keyout = NULL;
    uint8_t *p_request = NULL;
    size_t p_requestlen;
    uint8_t *m = NULL, *c = NULL, *c2 = NULL, *c_response = NULL;
    size_t mlen, clen, c2len, c_responselen;
    uint8_t nonce[crypto_box_NONCEBYTES];
    uint64_t timestamp;
    reencrypt_status ret = REENCRYPT_FAILED;

    // input checks - everything must be outside of the enclave
    if (!sgx_is_outside_enclave(clid, sizeof(client_id)) ||
        !sgx_is_outside_enclave(request, requestlen) ||
        !sgx_is_outside_enclave(response, *responselen) ||
        !sgx_is_outside_enclave(responselen, sizeof(size_t))) {
        ret = REENCRYPT_INVALID_INPUT;
        goto err;
    }

    if (!ctx.ready) {
        ret = REENCRYPT_NOT_READY;
        goto err;
    }

    // p_request needs to be freed
    if ((ret = unbox((uint8_t *)clid, ctx.sk, request, requestlen, &p_request,
                     &p_requestlen)) != REENCRYPT_OK) {
        goto err;
    }

    // c needs to be freed
    // NOTE: we could just point the outputs at their positions in the input,
    //		 and avoid allocating new memory and copy data.
    if ((ret = unpack_request(p_request, p_requestlen, &keyIDin, &keyIDout, &c,
                              &clen)) != REENCRYPT_OK) {
        goto err;
    }

    // keyin and keyout need to be key_free'd
    if ((ret = check_policy(&keyin, &keyout, *clid, keyIDin, keyIDout)) !=
        REENCRYPT_OK) {
        goto err;
    }

    // are the keys expired?
    if (ret = unsafe_timestamp(&timestamp) != REENCRYPT_OK) {
        goto err;
    }
    if (timestamp > keyin->expiration_date ||
        timestamp > keyout->expiration_date) {
        ret = REENCRYPT_KEY_EXPIRED;
        goto err;
    }

    // m needs to be freed
    if ((ret = decrypt(&m, &mlen, c, clen, keyin)) != REENCRYPT_OK) {
        goto err;
    }

    // c2 needs to be freed
    if ((ret = encrypt(&c2, &c2len, m, mlen, keyout)) != REENCRYPT_OK) {
        goto err;
    }

    // source a random nonce for the response
    {
        if (sgx_read_rand(nonce, crypto_box_NONCEBYTES) != SGX_SUCCESS)
        {
            ret = REENCRYPT_FAILED;
            goto err;
        }
    }
    // c_response needs to be freed
    if ((ret = box((uint8_t *)clid, ctx.sk, nonce, c2, c2len, &c_response,
                   &c_responselen)) != REENCRYPT_OK) {
        goto err;
    }
    // check if we have enough space to output the response
    if (c_responselen > *responselen) {
        ret = REENCRYPT_INCREASE_RESPONSE_SIZE;
        goto err;
    }
    // output response
    memcpy(response, c_response, c_responselen);
    *responselen = c_responselen;

    // life is good
    key_free(keyin);
    key_free(keyout);
    free(m);
    free(c);
    free(c2);
    free(c_response);
    return REENCRYPT_OK;
err:
    key_free(keyin);
    key_free(keyout);
    free(m);
    free(c);
    free(c2);
    free(c_response);
    return (ret != REENCRYPT_OK ? ret : REENCRYPT_FAILED);
}

/* REENCRYPT: Encryption function */
reencrypt_status encrypt(uint8_t **c, size_t *clen, const uint8_t *m,
                         const size_t mlen, const struct keydata_t *key) {
    uint8_t *temp = NULL;
    uint32_t templen;

    // calculate plaintext length
    templen = aes128gcm_ciphertext_size(mlen);
    // allocate memory for ciphertext
    temp = (uint8_t *)malloc(templen);
    if (temp == NULL)
        goto err;
    // encrypt
    if (aes128gcm_encrypt(&key->key, m, mlen, temp, templen)) {
        goto err;
    }
    *c = temp;
    *clen = templen;
    return REENCRYPT_OK;

err:
    free(temp);
    return REENCRYPT_FAILED;
}

/* REENCRYPT: Decryption function */
reencrypt_status decrypt(uint8_t **m, size_t *mlen, const uint8_t *c,
                         const size_t clen, const struct keydata_t *key) {
    uint8_t *temp = NULL;
    uint32_t templen;

    // calculate plaintext length
    templen = aes128gcm_plaintext_size(clen);
    // allocate memory for plaintext
    temp = (uint8_t *)malloc(templen);
    if (temp == NULL)
        goto err;
    // decrypt
    if (aes128gcm_decrypt(&key->key, c, clen, temp, templen)) {
        goto err;
    }

    // output result
    *m = temp;
    *mlen = templen;
    return REENCRYPT_OK;

err:
    free(temp);
    return REENCRYPT_FAILED;
}
