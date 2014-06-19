/*===-- misc/curve25519.h -------------------------------*- PUBLIC-*- H -*-===*/
/**
*** @file
*** @brief Misc. asymmetric module (temp)
***
*** This header provides access to the curve25519 asymmetric elliptic curve DH
*** algorithm. It is in this folder temporarily as an experimental module.
**/
/*===----------------------------------------------------------------------===*/

#ifndef ORDO_CURVE25519_H
#define ORDO_CURVE25519_H

/** @cond **/
#include "ordo/common/interface.h"
/** @endcond **/

#ifdef __cplusplus
extern "C" {
#endif

/*===----------------------------------------------------------------------===*/

#define curve25519_gen                   ordo_curve25519_gen
#define curve25519_pub                   ordo_curve25519_pub
#define curve25519_ecdh                  ordo_curve25519_ecdh

/*===----------------------------------------------------------------------===*/

/** Generates a random private key.
***
*** @param [out]    priv           Output buffer for the private key.
***
*** @returns \c #ORDO_SUCCESS on success, else an error code.
***
*** @remarks The private key is exactly 32 bytes (256 bits) long.
***
*** @remarks This function uses \c os_secure_random().
**/
ORDO_PUBLIC
int curve25519_gen(void *priv);

/** Retrieves the public key corresponding to a private key.
***
*** @param [out]    pub            Output buffer for the public key.
*** @param [in]     priv           The private key to be used.
***
*** @remarks The public key is exactly 32 bytes (256 bits) long.
***
*** @remarks The private key must be in the proper format - that is, correctly
***          masked according to the curve25519 specification (relating to the
***          first and last bytes of the private key).
**/
ORDO_PUBLIC
void curve25519_pub(void *pub, const void *priv);

/** Computes the shared secret between two keypairs.
***
*** @param [out]    shared         Output buffer for the shared secret.
*** @param [in]     priv           The private key of the first keypair.
*** @param [in]     other          The public key of the second keypair.
***
*** @remarks The shared secret is exactly 32 bytes (256 bits) long.
***
*** @warning This shared secret is \b unique to a given pair of keypairs, thus
***          it should be treated as long-term key material, i.e. don't use it
***          directly for encryption or other (derive secondary keys from it).
**/
ORDO_PUBLIC
void curve25519_ecdh(void *shared, const void *priv, const void *other);

/*===----------------------------------------------------------------------===*/

#ifdef __cplusplus
}
#endif

#endif
