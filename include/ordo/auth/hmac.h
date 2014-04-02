/*===-- auth/hmac.h ------------------------------------*- PUBLIC -*- H -*-===*/
/**
/// @file
/// @brief Module
///
/// Module  for computing  HMAC's (Hash-based  Message Authentication  Codes),
/// which securely combine  a hash function with a  cryptographic key securely
/// in order to provide both authentication and integrity, as per RFC 2104.
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

struct HMAC_CTX;

/** Allocates a new HMAC context.
///
/// @param [in]     hash           The hash function to use.
///
/// @return The allocated HMAC context, or \c 0 if allocation fails.
///
/// @remarks The PRF used for the HMAC will be the hash function as it behaves
///          with default parameters. It is not  possible to use hash function
///          extensions (e.g. Skein in specialized HMAC mode) via this module,
///          though if you intend to use a specific hash function you can just
///          skip this abstraction layer and directly use whatever features it
///          provides to compute message authentication codes.
**/
ORDO_PUBLIC
struct HMAC_CTX *hmac_alloc(const struct HASH_FUNCTION *hash);

/** Initializes an HMAC context, provided optional parameters.
///
/// @param [in]     ctx            An allocated HMAC context.
/// @param [in]     key            The cryptographic key to use.
/// @param [in]     key_len        The size, in bytes, of the key.
/// @param [out]    params         Hash function specific parameters.
///
/// @returns \c #ORDO_SUCCESS on success, else an error code.
///
/// @remarks The hash parameters apply to the inner hash operation only, which
///          is the one used to hash the passed key with the inner mask.
///
/// @remarks Do not use hash parameters which modify the output length or this
///          function's behavior is undefined.
**/
ORDO_PUBLIC
int hmac_init(struct HMAC_CTX *ctx,
              const void *key, size_t key_len,
              const void *params);

/** Updates an HMAC context, feeding more data into it.
///
/// @param [in]     ctx            An initialized HMAC context.
/// @param [in]     in             The data to feed into the context.
/// @param [in]     in_len         The length, in bytes, of the data.
///
/// @remarks This function has the same properties, with  respect to the input
///          buffer, as the \c digest_update() function.
**/
ORDO_PUBLIC
void hmac_update(struct HMAC_CTX *ctx,
                 const void *in, size_t in_len);

/** Finalizes a HMAC context, returning the final fingerprint.
///
/// @param [in]     ctx            An initialized HMAC context.
/// @param [out]    fingerprint    The output buffer for the fingerprint.
///
/// @returns \c #ORDO_SUCCESS on success, else an error code.
///
/// @remarks The fingerprint length is equal to the underlying hash function's
///          digest length, which may be queried via \c hash_digest_length().
**/
ORDO_PUBLIC
int hmac_final(struct HMAC_CTX *ctx, void *fingerprint);

/** Frees a digest context.
///
/// @param [in]     ctx            The HMAC context to be freed.
///
/// @remarks The  context need  not have been initialized, but if it has been,
///          it must have been finalized before calling this function.
///
/// @remarks Passing \c 0 to this function is valid, and will do nothing.
**/
ORDO_PUBLIC
void hmac_free(struct HMAC_CTX *ctx);

/** Performs a deep copy of one context into another.
///
/// @param [out]    dst            The destination context.
/// @param [in]     src            The source context.
///
/// @remarks The destination context should have been allocated using the same
///          primitive(s) as the source context, and mustn't be initialized.
///
/// @remarks The source context must be initialized.
**/
ORDO_PUBLIC
void hmac_copy(struct HMAC_CTX *dst,
               const struct HMAC_CTX *src);

/*===----------------------------------------------------------------------===*/

#ifdef __cplusplus
}
#endif

#endif
