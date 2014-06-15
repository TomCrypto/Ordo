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
    /** Desired output length, in \b bits.
    ***
    *** @warning This parameter affects the hash function's digest length.
    ***
    *** @remarks The actual output length will be in bytes, and this parameter
    ***          \b will be  truncated to a byte boundary, so this should be a
    ***          multiple of 8 to avoid any surprises.
    **/
    uint64_t out_len;
    /** Unused, should be left zero according to the Skein specification.
    **/
    uint8_t unused[16];
};
#pragma pack(pop)

/** Returns the default Skein-256 configuration block (parameters).
**/
ORDO_PUBLIC
struct SKEIN256_PARAMS skein256_default(void);

/*===----------------------------------------------------------------------===*/

#ifdef __cplusplus
}
#endif

#endif
