/*===-- common/identification.h ------------------------*- PUBLIC -*- H -*-===*/
/**
*** @file
*** @brief Utility
***
*** This header contains definitions assigning an identifier to each primitive
*** in the library - hash functions, block ciphers, modes of operation, and so
*** on - which can then be used in higher level API's for abstraction purposes
*** and more expressive code. This header also provides functionality relating
*** to primitive management, e.g. which primitives are available, etc...
***
*** Note the zero ID will always stand for an error situation e.g. a primitive
*** is not available. The zero ID is \b never a valid primitive identifier.
***
*** This also allows for a quick overview of what is implemented in Ordo.
**/
/*===----------------------------------------------------------------------===*/

#ifndef ORDO_IDENTIFICATION_H
#define ORDO_IDENTIFICATION_H

/** @cond **/
#include "ordo/common/interface.h"
/** @endcond **/

#ifdef __cplusplus
extern "C" {
#endif

/*===----------------------------------------------------------------------===*/

#define HASH_MD5                                                        0x8110
#define HASH_SHA256                                                     0x8010
#define HASH_SKEIN256                                                   0x8210

#define BLOCK_NULLCIPHER                                                0xFF20
#define BLOCK_THREEFISH256                                              0x1A20
#define BLOCK_AES                                                       0x0C20

#define STREAM_RC4                                                      0x3130

#define BLOCK_MODE_ECB                                                  0x8040
#define BLOCK_MODE_CBC                                                  0x8140
#define BLOCK_MODE_CTR                                                  0x8240
#define BLOCK_MODE_CFB                                                  0x8340
#define BLOCK_MODE_OFB                                                  0x8440

#define PRIM_TYPE_HASH                                                       1
#define PRIM_TYPE_BLOCK                                                      2
#define PRIM_TYPE_STREAM                                                     3
#define PRIM_TYPE_BLOCK_MODE                                                 4

/** @typedef prim_t
***
*** @brief Data type which holds a primitive identifier.
**/
typedef int prim_t;

/** Returns the name of a primitive.
***
*** @param [in]     prim           A primitive identifier.
***
*** @returns The name of the primitive as a human-readable string, or zero, if
***          the primitive does not exist (i.e. invalid identifier passed).
***
*** @remarks Do not rely on this being constant, use it for display only.
***
*** @remarks Will work even if the primitive is not available.
**/
ORDO_PUBLIC
const char *prim_name(prim_t prim);

/** Returns a primitive identifier from a name.
***
*** @param [in]     name           A primitive name.
***
*** @returns The corresponding primitive identifier, or zero on error.
***
*** @remarks Will work even if the primitive is not available.
**/
ORDO_PUBLIC
prim_t prim_from_name(const char *name);

/** Checks whether a primitive is available.
***
*** @param [in]     prim           A primitive identifier.
***
*** @returns 0 if the primitive is not available, 1 otherwise.
**/
ORDO_PUBLIC
int prim_available(prim_t prim);

/** Returns a list of available primitives of a given type.
***
*** @param [in]     type           A primitive type.
***
*** @returns A zero-terminated list of such primitives.
***
*** @remarks Passing zero returns all available primitives.
**/
ORDO_PUBLIC
const prim_t *prim_from_type(int type);

/** Returns the type of a given primitive.
***
*** @param [in]     prim           A primitive identifier.
***
*** @returns The type of the primitive, or zero on error.
***
*** @warning Will \b not work if the primitive is not available.
**/
ORDO_PUBLIC
int prim_type(int prim);

/*===----------------------------------------------------------------------===*/

#ifdef __cplusplus
}
#endif

#endif
