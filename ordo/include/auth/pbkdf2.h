#ifndef PBKDF2_H
#define PBKDF2_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file pbkdf2.h
 *
 * \brief PBKDF2 interface.
 *
 * Interface to compute PBKDF2 digests (Password-Based Key Derivation Function v2), which combine
 * a keyed PRF (here HMAC) with a salt in order to generate secure cryptographic keys, as per RFC
 * 2898. Also features a variable iteration count (work factor).
 *
 * Unlike most cryptographic interfaces, the PBKDF2 API does not follow the usual init/update/final
 * pattern but is a context-free function.
 *
 * @see pbkdf2.c
 */

#include <primitives/primitives.h>
#include <hash/hash.h>
#include <auth/hmac.h>

/*! Computes a PBKDF2 digest.
 \param hash The hash function to use (the PRF used will be HMAC instantiated with this hash function)
 \param password A pointer to the password to use.
 \param passwordLen The length in bytes of the \c password buffer.
 \param salt a pointer to the salt to use.
 \param saltLen The length in bytes of the \c salt buffer.
 \param iterations The number of PBKDF2 iterations to use.
 \param outputLen The length, in bytes, of the output digest.
 \param digest A pointer to a buffer in which to write the output digest. Must be at least
               \c outputLen bytes long.
 \param hashParams A pointer to hash-specific parameters, or zero if not used.
 \return Returns \c ORDO_ESUCCESS on success, and a negative value on error. */
int pbkdf2(HASH_FUNCTION* hash, void *password, size_t passwordLen, void *salt,
          size_t saltLen, size_t iterations, size_t outputLen, void *digest,
          void *hashParams);

#ifdef __cplusplus
}
#endif

#endif
