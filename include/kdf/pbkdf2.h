#ifndef ORDO_PBKDF2_H
#define ORDO_PBKDF2_H

#include "digest/digest.h"

/******************************************************************************/

/*!
 * @file pbkdf2.h
 * @brief PBKDF2 module.
 *
 * Module for the PBKDF2 algorithm (Password-Based Key Derivation Function v2)
 * which combines a keyed PRF (here HMAC) with a salt in order to generate
 * secure cryptographic keys, as per RFC 2898. Also features a variable
 * iteration count (work factor) to help thwart brute-force attacks.
 *
 * Unlike most other cryptographic modules, the PBKDF2 API does not follow the
 * traditional init/update/final pattern but is a context-free function as its
 * inputs are almost always known in advance. As such this module does not
 * benefit from the use of contexts.
*/

#ifdef __cplusplus
extern "C" {
#endif

/*! Derives a key using PBKDF2.
 *  @param hash The hash function to use (the PRF used will be generic HMAC
 *              instantiated with this hash function)
 *  @param params Hash-specific parameters, or nil if not used.
 *  @param password The password to derive a key from.
 *  @param password_len The length in bytes of the \c password buffer.
 *  @param salt The cryptographic salt to use.
 *  @param salt_len The length in bytes of the \c salt buffer.
 *  @param iterations The number of PBKDF2 iterations to use.
 *  @param out A buffer to which to write the derived key.
 *  @param out_len The desired length, in bytes, of the derived key. The \c out
 *                 buffer should be at least \c out_len bytes long.
 *  @return Returns \c #ORDO_SUCCESS on success, or an error code.
 *  @remarks There is a maximum output length of 2^32 - 1 multiplied by the
 *           digest length of the chosen hash function, but it is unlikely
 *           to be reached as derived keys are generally no longer than
 *           a few hundred bits. Reaching the limit will result in an
 *           \c #ORDO_ARG error code. This limit is mandated by the
 *           PBKDF2 specification.
 *  @remarks Do not use hash parameters which modify the hash function's output
 *           length, or this function's behavior is undefined.
*/
int pbkdf2(const struct HASH_FUNCTION *hash,
           const void *params,
           const void *password,
           size_t password_len,
           const void *salt,
           size_t salt_len,
           size_t iterations,
           void *out,
           size_t out_len);

#ifdef __cplusplus
}
#endif

#endif
