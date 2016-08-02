# SGX-reencrypt 

**Disclaimer**: This is a PoC of an SGX-based application, but is
insecure as it is. To build secure SGX-based applications, you'll need
to perform the remote attestation step after being approved as an SGX
licensee. Even if you managed to get an attested release-mode enclave
from our code you shouldn't use it to protect real stuff; neither the
architecture nor the code have been properly reviewed, hence they're
probably not secure.


## Introduction

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

Responses are encrypted too using `crypto_box()`, and error responses
include `C` to make them indistinguishable from success responses.

This assumes that keys and a policy have been sealed to the reencrypt
enclave, as well as the enclave's Curve25519 private key.


## Setup 

A enclave's TweetNaCl keypair needs to be generated before using it.
The enclave provides the trusted call `generate_keypair`, that will
generate a new keypair and output the public key on success. This
information can be sealed to the filesystem using the trusted call
`seal_keypair`. After service restart, `unseal_keypair` will try to
recover the previously sealed keypair.

Once an enclave keypair has been generated, the returned public key
can be distributed amongst clients; it will be used to encrypt each
request and authenticate responses.

## Usage

The SGX-reencrypt functionality is accessed through two trusted calls
(ecalls): `register_key()` and `reencrypt()`. Both accept an encrypted
request and returns an encrypted response that can be opened using the
client private key and the enclave public key.

### Key registration

Key registration is the process by which symmetric keys are provisioned
to the enclave. These keys can later be used during reencryption
requests to decrypt and encrypt given ciphertexts.

Each key registration request is composed by an encrypted datagram,
using the enclave public key, containing these fields:

 * `key`, 16 bytes: 128bit AES key used for encryption and decryption

 * `expiration_date`, 8 bytes: todo

 * `policy_from`, 1 byte: ...

 * `n_keys_from`, 4 bytes: ...

 * `policy_to`, 1 byte: ...

 * `n_keys_to`, 4 bytes: ...

 * `n_authorized_clients`, 4 bytes: ...

 * `keys_from`, [16 bytes]: ...

 * `keys_to`, [16 bytes]: ...

 * `authorized_clients`, [32 bytes]: ...

On success, the enclave response contains the 16-byte key ID assigned.

#### Key ID generation

At the moment, 16-byte BLAKE2b(key || expiration_date). No salt/nonce.
See security note 1.

#### Client authentication

Each authorized client is authenticated using its TweetNaCl public key.

### Reencryption

Reencryption is the process by which, given a ciphertext, `c`, and a
pair of previously registered key identifiers, `k1id`, `k2id`, the user
gets the new ciphertext `encrypt(k2, decrypt(k1, c))`. This process
allows to reencrypt a given ciphertext without exposing the plaintext
nor the keys to observers out of the enclave.

Each key reencryption request is composed by an encrypted datagram,
using the enclave public key, containing these fields:

 [K1ID   (16bytes)][K2ID   (16bytes)][IV (12bytes)]
 [MAC    (16bytes)][ciphertext               (...)]

On success, the enclave response contains a new ciphertext.

#### Policy check

Given a reencryption request, a set of policies is enforced:

 1. Does key-in allows encryption to key-out?

 2. Does key-out allows encryption from key-in?

 3. Is the client authorized to use key-in and key-out?

 4. Is the current timestamp lower than key-in and key-out exp. date?
    See security note 2.

Only when every policy is passed the reencryption is computed.

## Security

 * An eavesdropper on the channel shouldn't be able to extract clear
   information about the requests nor the responses (only relative
   data, as request size).

 * An attacker that interacts with the enclave shouldn't be able to
   extract the keys.

 * Non-authorized users shouldn't be able to use registered keys.

 * Ciphertexts should be indistinguishable.

## Security notes

(1) As Key ID is deterministic, a party knowing a symmetric key and
expiration date could overwrite the registered key and replace the
policy with a malicious one without the user noticing it.

(2) At the moment, there's no trusted absolute time source inside the
enclave, and the timestamp is requested through an untrusted call to
the system, rendering the expiration date policy forgeable by a 
malicious enclave host.

## Intellectual property

Copyright (c) 2016, Nagravision S.A.

Code under GPLv3
