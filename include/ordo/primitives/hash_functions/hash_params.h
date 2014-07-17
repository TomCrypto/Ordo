/*===-- primitives/hash_functions/hash_params.h --------*- PUBLIC -*- H -*-===*/
/**
*** @file
*** @brief Primitive Parameters
***
*** This header contains parameter structures for all hash functions.
**/
/*===----------------------------------------------------------------------===*/

#ifndef ORDO_HASH_PARAMS_H
#define ORDO_HASH_PARAMS_H

/** @cond **/
#include "ordo/common/interface.h"
/** @endcond **/

#ifdef __cplusplus
extern "C" {
#endif

/*===----------------------------------------------------------------------===*/

#define skein256_default                 ordo_skein256_default

/*===----------------------------------------------------------------------===*/

/** @brief Skein-256 hash function parameters.
***
*** @remarks Refer to the Skein specification to  know more about what each of
***          these parameter fields stand for.
***
*** @warning This structure is \b packed, to improve performance while hashing
***          the configuration block, be careful when taking pointers to it.
**/
#pragma pack(push,1)
struct SKEIN256_PARAMS
{
    /** The schema identifier, on four bytes.
    **/
    uint8_t schema[4];
    /** The version number, on two bytes.
    **/
    uint8_t version[2];
    /** Reserved, should be left zero according to the Skein specification.
    **/
    uint8_t reserved[2];
    /** Hash function output length, in \b bits.
    ***
    *** @warning This parameter affects the hash function's digest length.
    ***
    *** @warning Must be 256 or \c skein256_init() will return \c ORDO_ARG.
    **/
    uint64_t out_len;
    /** Unused, should be left zero according to the Skein specification.
    **/
    uint8_t unused[16];
};
#pragma pack(pop)

/** @brief Polymorphic hash function parameter union.
**/
union HASH_PARAMS
{
    struct SKEIN256_PARAMS               skein256;
};

/** Returns the default Skein-256 configuration block (parameters).
**/
ORDO_PUBLIC
struct SKEIN256_PARAMS skein256_default(void);

/*===----------------------------------------------------------------------===*/

#ifdef __cplusplus
}
#endif

#endif
