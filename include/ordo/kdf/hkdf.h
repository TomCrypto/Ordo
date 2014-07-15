/*===-- kdf/hkdf.h -------------------------------------*- PUBLIC -*- H -*-===*/
/**
*** @file
*** @brief Module
***
*** Module for the HMAC-based Extract-and-Expand Key Derivation Function. HKDF
*** is a key stretching function which takes in a cryptographically secure key
*** (\b not a password) and an optional salt, and generates a longer keystream
*** deterministically.
***
*** Just like PBKDF2, HKDF does not require the use of contexts.
**/
/*===----------------------------------------------------------------------===*/

#ifndef ORDO_HDKF_H
#define ORDO_HDKF_H

/** @cond **/
#include "ordo/common/interface.h"
/** @endcond **/

#ifdef __cplusplus
extern "C" {
#endif

/*===----------------------------------------------------------------------===*/

#define kdf_hkdf                         ordo_kdf_hkdf

/*===----------------------------------------------------------------------===*/

/** Derives a key using HKDF.
***
*** @param [in]     hash           The hash function to use (the PRF used will
***                                be an instantiation of HMAC with it).
*** @param [in]     params         Hash-specific parameters.
*** @param [in]     key            The key to derive a keystream from.
*** @param [in]     key_len        The length in bytes of the key.
*** @param [in]     salt           The cryptographic salt to use.
*** @param [in]     salt_len       The length in bytes of the salt.
*** @param [in]     info           An application specific string.
*** @param [in]     info_len       The length in bytes of the info string.
*** @param [out]    out            The output buffer for the derived key.
*** @param [in]     out_len        The required length, in bytes, of the key.
***
*** @returns \c #ORDO_SUCCESS on success, else an error code.
***
*** @remarks The salt may be zero-length in which case the buffer may be zero,
***          and the info buffer may be zero-length as well.
***
*** @remarks The password or out buffers cannot be zero-length.
***
*** @warning There is a maximum output length, of 255 multiplied by the digest
***          length of the chosen hash function. This is by design.
***
*** @remarks The \c out buffer should be at least \c out_len bytes long.
***
*** @warning Do not use hash parameters which modify the output length or this
***          function's behavior is undefined (use \c out_len instead, this is
***          the whole point of this algorithm).
**/
ORDO_PUBLIC
int kdf_hkdf(prim_t hash, const void *params,
             const void *key, size_t key_len,
             const void *salt, size_t salt_len,
             const void *info, size_t info_len,
             void *out, size_t out_len);

/*===----------------------------------------------------------------------===*/

#ifdef __cplusplus
}
#endif

#endif
