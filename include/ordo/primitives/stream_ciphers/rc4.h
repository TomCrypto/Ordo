/*===-- primitives/stream_ciphers/rc4.h ----------------*- PUBLIC -*- H -*-===*/
/**
*** @file
*** @brief Primitive
***
*** RC4 is a  stream cipher, which accepts  keys between 40 and  2048 bits (in
*** multiples of 8 bits only). It accepts a parameter consisting of the number
*** of  initial  keystream  bytes  to drop  immediately  after  key  schedule,
*** effectively implementing RC4-drop[n]. If no  drop parameter is passed, the
*** implementation drops 2048 bytes by default.
***
*** Be aware that even with a drop, it isn't secure to encrypt more than a few
*** hundred megabytes of data with the same key (due to a distinguisher attack
*** that can distinguish between an RC4 keystream and a random stream). If you
*** are concerned, use a different algorithm or rekey at generous intervals.
**/
/*===----------------------------------------------------------------------===*/

#ifndef ORDO_RC4_H
#define ORDO_RC4_H

/** @cond **/
#include "ordo/common/interface.h"
/** @endcond **/

#include "ordo/primitives/stream_ciphers.h"

#ifdef __cplusplus
extern "C" {
#endif

/*===----------------------------------------------------------------------===*/

#define rc4_init                         ordo_rc4_init
#define rc4_update                       ordo_rc4_update
#define rc4_final                        ordo_rc4_final
#define rc4_query                        ordo_rc4_query
#define rc4_bsize                        ordo_rc4_bsize

/*===----------------------------------------------------------------------===*/

/** @see \c stream_init()
***
*** @retval #ORDO_KEY_LEN if the key length was less than 40 bits (5 bytes) or
***                       more than 2048 bits (256 bytes).
***
*** @remarks The amount of keystream bytes to drop can be set via the \c params
***          argument, see \c RC4_PARAMS. By default, 2048 bytes are dropped.
**/
ORDO_PUBLIC
int rc4_init(struct RC4_STATE *state,
             const void *key, size_t key_len,
             const struct RC4_PARAMS *params);

/** @see \c stream_update()
**/
ORDO_PUBLIC
void rc4_update(struct RC4_STATE *state,
                void *buffer, size_t len);

/** @see \c stream_final()
**/
ORDO_PUBLIC
void rc4_final(struct RC4_STATE *state);

/** @see \c stream_query()
**/
ORDO_PUBLIC
size_t rc4_query(int query, size_t value);

/** Gets the size in bytes of an \c RC4_STATE.
***
*** @returns The size in bytes of the structure.
***
*** @remarks Binary compatibility layer.
**/
ORDO_PUBLIC
size_t rc4_bsize(void);

/*===----------------------------------------------------------------------===*/

#ifdef __cplusplus
}
#endif

#endif
