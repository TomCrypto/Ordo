/*===-- primitives/block_ciphers/block_params.h --------*- PUBLIC -*- H -*-===*/
/**
*** @file
*** @brief Primitive Parameters
***
*** This header contains parameter structures for all block ciphers.
**/
/*===----------------------------------------------------------------------===*/

#ifndef ORDO_BLOCK_PARAMS_H
#define ORDO_BLOCK_PARAMS_H

/** @cond **/
#include "ordo/common/interface.h"
/** @endcond **/

#ifdef __cplusplus
extern "C" {
#endif

/*===----------------------------------------------------------------------===*/

/** @brief Threefish-256 block cipher parameters.
**/
struct THREEFISH256_PARAMS
{
    /** The tweak word, on a pair of 64-bit words.
    **/
    uint64_t tweak[2];
};

/** @brief AES block cipher parameters.
**/
struct AES_PARAMS
{
    /** The number of rounds to use.
    ***
    *** @remarks The defaults  are 10 for a 128-bit key, 12 for a 192-bit key,
    ***          14 for a 256-bit key, and are standardized. It is \b strongly
    ***          discouraged to lower the number of rounds below the defaults.
    **/
    size_t rounds;
};

/*===----------------------------------------------------------------------===*/

#ifdef __cplusplus
}
#endif

#endif
