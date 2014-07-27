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

#define prim_avail                       ordo_prim_avail
#define prim_name                        ordo_prim_name
#define prim_type                        ordo_prim_type
#define prim_from_name                   ordo_prim_from_name
#define prims_by_type                    ordo_prims_by_type
#define prim_default                     ordo_prim_default

/*===----------------------------------------------------------------------===*/

/** @enum PRIM_TYPE
***
*** Enumerates the different types of primitives (values start at 1).
**/
enum PRIM_TYPE
{
    PRIM_TYPE_UNKNOWN = 0,
    PRIM_TYPE_HASH,
    PRIM_TYPE_BLOCK,
    PRIM_TYPE_STREAM,
    PRIM_TYPE_BLOCK_MODE
};

/** @typedef prim_t
***
*** @brief Data type which holds a primitive identifier.
**/
typedef int prim_t;

/** Value representing an unknown primitive, defined as zero.
***
*** @remarks You can use this to check for errors or for comparisons.
**/
#define PRIM_UNKNOWN                                          ((prim_t)0x0000)

#define HASH_MD5                                              ((prim_t)0x8110)
#define HASH_SHA1                                             ((prim_t)0x8310)
#define HASH_SHA256                                           ((prim_t)0x8010)
#define HASH_SKEIN256                                         ((prim_t)0x8210)

#define BLOCK_NULLCIPHER                                      ((prim_t)0xFF20)
#define BLOCK_THREEFISH256                                    ((prim_t)0x1A20)
#define BLOCK_AES                                             ((prim_t)0x0C20)

#define STREAM_RC4                                            ((prim_t)0x3130)

#define BLOCK_MODE_ECB                                        ((prim_t)0x8040)
#define BLOCK_MODE_CBC                                        ((prim_t)0x8140)
#define BLOCK_MODE_CTR                                        ((prim_t)0x8240)
#define BLOCK_MODE_CFB                                        ((prim_t)0x8340)
#define BLOCK_MODE_OFB                                        ((prim_t)0x8440)

/** Checks whether a primitive is available.
***
*** @param [in]     prim           A primitive identifier.
***
*** @returns 0 if the primitive is not available, 1 otherwise.
**/
ORDO_PUBLIC
int prim_avail(prim_t prim);

/** Returns the name of a primitive.
***
*** @param [in]     prim           A primitive identifier.
***
*** @returns The name of the primitive as a human-readable string, or zero, if
***          the primitive does not exist (i.e. invalid identifier passed).
***
*** @remarks Do not rely on this being constant, use it for display only.
***
*** @warning Will \b not work if the primitive is not available.
**/
ORDO_PUBLIC
const char *prim_name(prim_t prim);

/** Returns the type of a given primitive.
***
*** @param [in]     prim           A primitive identifier.
***
*** @returns The type of the primitive, or zero on error.
***
*** @warning Will \b not work if the primitive is not available.
**/
ORDO_PUBLIC
enum PRIM_TYPE prim_type(prim_t prim);

/** Returns a primitive identifier from a name.
***
*** @param [in]     name           A primitive name.
***
*** @returns The corresponding primitive identifier, or zero on error.
***
*** @warning Will \b not work if the primitive is not available.
**/
ORDO_PUBLIC
prim_t prim_from_name(const char *name);

/** Returns a list of available primitives of a given type.
***
*** @param [in]     type           A primitive type.
***
*** @returns A zero-terminated list of such primitives.
**/
ORDO_PUBLIC
const prim_t *prims_by_type(enum PRIM_TYPE type);

/** Returns the default available primitive of a given type.
***
*** @param [in]     type           A primitive type.
***
*** @returns The default primitive, or zero if none exists.
***
*** @warning It is recommended to keep at least one primitive of every type in
***          the library, in order for some software (e.g. the test driver) to
***          work properly, but this is not strictly required (so that heavily
***          stripped builds of the library will still work properly).
***
*** @warning The return value of this function depends on which primitives are
***          available, and even though they are loosely prioritized, based on
***          an arbitrary strength/performance scale, there is *absolutely* no
***          guarantee the primitive returned will be suitable for use (in the
***          context of your application). Use this when you do not care about
***          the characteristics of a primitive beyond its type.
**/
ORDO_PUBLIC
prim_t prim_default(enum PRIM_TYPE type);

/*===----------------------------------------------------------------------===*/

#ifdef __cplusplus
}
#endif

#endif
