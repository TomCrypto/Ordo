/*===-- kdf/pbkdf2.h -----------------------------------*- PUBLIC -*- H -*-===*/
/**
*** @file
*** @brief Module
***
*** Module for  the PBKDF2  algorithm (Password-Based Key  Derivation Function
*** v2)  which combines  a keyed  PRF  (here HMAC)  with  a salt  in order  to
*** generate  secure cryptographic  keys, as  per  RFC 2898.  Also features  a
*** variable iteration count (work factor) to help thwart brute-force attacks.
***
*** Unlike most  other cryptographic modules,  the PBKDF2 API does  not follow
*** the traditional  init/update/final pattern but is  a context-free function
*** as its inputs are almost always known in advance. As such this module does
*** not benefit from the use of contexts.
**/
/*===----------------------------------------------------------------------===*/

#ifndef ORDO_PBKDF2_H
#define ORDO_PBKDF2_H

/** @cond **/
#include "ordo/common/interface.h"
/** @endcond **/

#include "ordo/auth/hmac.h"

#ifdef __cplusplus
extern "C" {
#endif

/*===----------------------------------------------------------------------===*/

#define kdf_pbkdf2                       ordo_kdf_pbkdf2

/*===----------------------------------------------------------------------===*/

/** Derives a key using PBKDF2.
***
*** @param [in]     hash           The hash function to use (the PRF used will
***                                be an instantiation of HMAC with it)
*** @param [in]     params         Hash-specific parameters.
*** @param [in]     password       The password to derive a key from.
*** @param [in]     password_len   The length in bytes of the password.
*** @param [in]     salt           The cryptographic salt to use.
*** @param [in]     salt_len       The length in bytes of the salt.
*** @param [in]     iterations     The number of PBKDF2 iterations to use.
*** @param [out]    out            The output buffer for the derived key.
*** @param [in]     out_len        The required length, in bytes, of the key.
***
*** @returns \c #ORDO_SUCCESS on success, else an error code.
***
*** @remarks There is a maximum output length of 2^32 - 1 multiplied by the
***          digest length of the chosen hash function, but it is unlikely
***          to be reached as derived keys are generally no longer than
***          a few hundred bits. Reaching the limit will result in an
***          \c #ORDO_ARG error code. This limit is mandated by the
***          PBKDF2 specification.
***
*** @remarks The \c out buffer should be at least \c out_len bytes long.
***
*** @warning Do not use hash parameters which modify the output length or this
***          function's behavior is undefined (use \c out_len instead).
**/
ORDO_PUBLIC
int kdf_pbkdf2(prim_t hash, const void *params,
               const void *password, size_t password_len,
               const void *salt, size_t salt_len,
               size_t iterations,
               void *out, size_t out_len);

/*===----------------------------------------------------------------------===*/

#ifdef __cplusplus
}
#endif

#endif
