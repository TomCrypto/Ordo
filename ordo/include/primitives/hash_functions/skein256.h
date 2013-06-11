#ifndef SKEIN256_H
#define SKEIN256_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file skein256.h
 *
 * \brief Skein-256 hash function.
 *
 * This is the Skein-256 hash function, which produces a 256-bit digest by default (but has parameters to output a
 * longer digest) and has a 256-bit internal state. This implementation supports messages up to a length of 2^64 - 1
 * bytes instead of the 2^96 - 1 available, but we trust this will not be an issue. This is a rather flexible hash
 * with lots of options. The following features are marked [x] if available, [ ] otherwise:
 *
 * [x] Simple hashing (256-bit digest, any-length message) \n
 * [x] Variable-length output (any-length digest, any-length message, uses parameters) \n
 * [x] Semi-personalizable configuration block (everything is changeable, but generally you should only change the
 * output length field if you want to remain compliant) \n
 * [ ] Personalization block \n
 * [ ] HMAC block \n
 * [ ] Other blocks \n
 *
 * \todo Expand Skein-256 parameters (add possible extra blocks, such as personalization, hmac, nonce, etc...). This
 * will probably require a rewrite of the UBI subsystem which is rather hardcoded and rigid at the moment.
 *
 * \todo Rewrite the UBI code properly.
 *
 * @see skein256.c
 */

#include <primitives/primitives.h>

/*! \brief Skein-256 hash parameters.
 *
 * A parameter structure for Skein-256. */
typedef struct SKEIN256_PARAMS
{
    /*! The schema identifier, on four bytes. */
    uint8_t schema[4];
    /*! The version number, on two bytes. */
    uint8_t version[2];
    /*! Reserved - must be left zero. */
    uint8_t reserved[2];
    /*! Desired output length, in bits (note the actual output digest will be truncated to a byte boundary, so this should really always be a multiple of 8). */
    uint64_t outputLength;
    /*! Unused, must be left zero. */
    uint8_t unused[16];
} SKEIN256_PARAMS;

HASH_FUNCTION_CONTEXT* Skein256_Create();

int Skein256_Init(HASH_FUNCTION_CONTEXT* ctx, SKEIN256_PARAMS* params);

void Skein256_Update(HASH_FUNCTION_CONTEXT* ctx, void* buffer, size_t size);

void Skein256_Final(HASH_FUNCTION_CONTEXT* ctx, void* digest);

void Skein256_Free(HASH_FUNCTION_CONTEXT* ctx);

void Skein256_Copy(HASH_FUNCTION_CONTEXT* dst, HASH_FUNCTION_CONTEXT* src);

void Skein256_SetPrimitive(HASH_FUNCTION* hash);

#ifdef __cplusplus
}
#endif

#endif
