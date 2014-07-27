/*===-- auth/hmac.h ------------------------------------*- PUBLIC -*- H -*-===*/
/**
*** @file
*** @brief Module
***
*** Module  for computing  HMAC's (Hash-based  Message Authentication  Codes),
*** which combine  a hash function with a  cryptographic key securely in order
*** to provide both authentication and integrity, as per RFC 2104.
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

#define hmac_init                        ordo_hmac_init
#define hmac_update                      ordo_hmac_update
#define hmac_final                       ordo_hmac_final
#define hmac_bsize                       ordo_hmac_bsize

/*===----------------------------------------------------------------------===*/

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
*** @remarks The hash parameters apply to the inner hash operation only, which
***          is the one used to hash the raw message and masked key.
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
***          digest length, which can be queried via \c hash_digest_length().
**/
ORDO_PUBLIC
int hmac_final(struct HMAC_CTX *ctx, void *fingerprint);

/** Gets the size in bytes of an \c HMAC_CTX.
***
*** @returns The size in bytes of the structure.
***
*** @remarks Binary compatibility layer.
**/
ORDO_PUBLIC
size_t hmac_bsize(void);

/*===----------------------------------------------------------------------===*/

#ifdef __cplusplus
}
#endif

#endif
