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
**/
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

/** @brief Polymorphic hash function parameter union.
**/
union HASH_PARAMS
{
    struct SKEIN256_PARAMS               skein256;
};

/** @brief The default Skein-256 configuration block.
**/
#define SKEIN256_PARAMS_DEFAULT\
    {{ 0x53, 0x48, 0x41, 0x33 }, { 1, 0 }, { 0 }, 256, { 0 }}

/*===----------------------------------------------------------------------===*/

#ifdef __cplusplus
}
#endif

#endif
