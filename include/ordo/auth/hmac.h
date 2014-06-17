/*===-- auth/hmac.h ------------------------------------*- PUBLIC -*- H -*-===*/
/**
*** @file
*** @brief Module
***
*** Module  for computing  HMAC's (Hash-based  Message Authentication  Codes),
*** which securely combine  a hash function with a  cryptographic key securely
*** in order to provide both authentication and integrity, as per RFC 2104.
**/
/*===----------------------------------------------------------------------===*/

#ifndef ORDO_HMAC_H
#define ORDO_HMAC_H

/** @cond **/
#include "ordo/common/interface.h"
/** @endcond **/

#include "ordo/digest/digest.h"

#ifdef __cplusplus
extern "C" {
#endif

/*===----------------------------------------------------------------------===*/

struct HMAC_CTX
{
    struct DIGEST_CTX dgt, outer;
    unsigned char key[HASH_BLOCK_LEN];
};

/** Initializes an HMAC context, provided optional parameters.
***
*** @param [in]     ctx            An allocated HMAC context.
*** @param [in]     key            The cryptographic key to use.
*** @param [in]     key_len        The size, in bytes, of the key.
*** @param [out]    hash           A hash function primitive to use.
*** @param [out]    params         Hash function specific parameters.
***
*** @returns \c #ORDO_SUCCESS on success, else an error code.
***
*** @remarks The hash parameters apply to the outer hash operation only, which
***          is the one used to hash the processed message and masked key.
**/
ORDO_PUBLIC
int hmac_init(struct HMAC_CTX *ctx,
              const void *key, size_t key_len,
              prim_t hash, const void *params);

/** Updates an HMAC context, feeding more data into it.
***
*** @param [in]     ctx            An initialized HMAC context.
*** @param [in]     in             The data to feed into the context.
*** @param [in]     in_len         The length, in bytes, of the data.
***
*** @remarks This function has the same properties, with  respect to the input
***          buffer, as the \c digest_update() function.
**/
ORDO_PUBLIC
void hmac_update(struct HMAC_CTX *ctx,
                 const void *in, size_t in_len);

/** Finalizes a HMAC context, returning the final fingerprint.
***
*** @param [in]     ctx            An initialized HMAC context.
*** @param [out]    fingerprint    The output buffer for the fingerprint.
***
*** @returns \c #ORDO_SUCCESS on success, else an error code.
***
*** @remarks The fingerprint length is equal to the underlying hash function's
***          digest length, which must be queried via \c hash_digest_length(),
***          or to the provided length, if a parameter which modified the hash
***          function's output length was passed to \c hmac_init().
**/
ORDO_PUBLIC
int hmac_final(struct HMAC_CTX *ctx, void *fingerprint);

/*===----------------------------------------------------------------------===*/

#ifdef __cplusplus
}
#endif

#endif
