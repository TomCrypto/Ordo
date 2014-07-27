/*===-- common/limits.h --------------------------------*- PUBLIC -*- H -*-===*/
/**
*** @file
*** @brief Utility
***
*** This header contains limit structures for the various primitives.
***
*** Limits of the form (min, max, mul) define a sequence of values of the form
***
***     [min, min + mul, min + 2 * mul, ..., max]
***
*** with the property that both min and max are multiples of mul, and that mul
*** is nonzero. If min is equal to max, then mul is set to 1 by convention (in
*** fact it should be set to zero, but setting it to 1 helps user code, by not
*** allowing the potential for division by 0 when checking for divisibility).
**/
/*===----------------------------------------------------------------------===*/

#ifndef ORDO_LIMITS_H
#define ORDO_LIMITS_H

/** @cond **/
#include "ordo/common/interface.h"
/** @endcond **/

#ifdef __cplusplus
extern "C" {
#endif

/*===----------------------------------------------------------------------===*/

/** @struct BLOCK_LIMITS
***
*** @brief Limit structure for block ciphers.
***
*** @var size_t BLOCK_LIMITS::key_min
***
*** The minimum key length in bytes.
***
*** @var size_t BLOCK_LIMITS::key_max
***
*** The maximum key length in bytes.
***
*** @var size_t BLOCK_LIMITS::key_mul
***
*** The number of bytes the key length must be a multiple of.
***
*** @remarks If \c key_min equals \c key_max, this is set to 1.
***
*** @var size_t BLOCK_LIMITS::block_size
***
*** The block size of the block cipher in bytes.
**/
struct BLOCK_LIMITS
{
    size_t key_min, key_max, key_mul;
    size_t block_size;
};

/** @struct BLOCK_MODE_LIMITS
***
*** @brief Limit structure for block modes.
***
*** @var size_t BLOCK_MODE_LIMITS::iv_min
***
*** The minimum initialization vector length in bytes.
***
*** @var size_t BLOCK_MODE_LIMITS::iv_max
***
*** The maximum initialization vector length in bytes.
***
*** @var size_t BLOCK_MODE_LIMITS::iv_mul
***
*** The number of bytes the IV length must be a multiple of.
***
*** @remarks If \c iv_min equals \c iv_max, this is set to 1.
**/
struct BLOCK_MODE_LIMITS
{
    size_t iv_min, iv_max, iv_mul;
};

/** @struct HASH_LIMITS
***
*** @brief Limit structure for hash functions.
***
*** @var size_t HASH_LIMITS::block_size
***
*** The block size of the hash function in bytes.
***
*** @var size_t HASH_LIMITS::digest_len
***
*** The digest length of the hash function in bytes.
**/
struct HASH_LIMITS
{
    size_t block_size;
    size_t digest_len;
};

/** @struct STREAM_LIMITS
***
*** @brief Limit structure for stream ciphers.
***
*** @var size_t STREAM_LIMITS::key_min
***
*** The minimum key length in bytes.
***
*** @var size_t STREAM_LIMITS::key_max
***
*** The maximum key length in bytes.
***
*** @var size_t STREAM_LIMITS::key_mul
***
*** The number of bytes the key length must be a multiple of.
***
*** @remarks If \c key_min equals \c key_max, this is set to 1.
**/
struct STREAM_LIMITS
{
    size_t key_min, key_max, key_mul;
};

/*===----------------------------------------------------------------------===*/

#ifdef __cplusplus
}
#endif

#endif
