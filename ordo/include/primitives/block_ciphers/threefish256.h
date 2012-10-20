#ifndef THREEFISH256_H
#define THREEFISH256_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file threefish256.h
 *
 * \brief Threefish-256 block cipher.
 *
 * Threefish-256 is a block cipher, which has a 256-bit block size and a 256-bit key size. It also has an optional
 * 128-bit tweak. The tweak can be set through the cipher parameters.
 *
 * @see threefish256.c
 */

#include <primitives/primitives.h>

/*! \brief Threefish-256 cipher parameters.
 *
 * A parameter structure for Threefish-256 - contains the 128-bit tweak word. */
typedef struct THREEFISH256_PARAMS
{
    /*! The tweak word, on a pair of 64-bit words. */
    uint64_t tweak[2];
} THREEFISH256_PARAMS;

BLOCK_CIPHER_CONTEXT* Threefish256_Create();

int Threefish256_Init(BLOCK_CIPHER_CONTEXT* ctx, UINT256_64* key, size_t keySize, THREEFISH256_PARAMS* params);

void Threefish256_Forward(BLOCK_CIPHER_CONTEXT* ctx, UINT256_64* block);

void Threefish256_Inverse(BLOCK_CIPHER_CONTEXT* ctx, UINT256_64* block);

void Threefish256_Free(BLOCK_CIPHER_CONTEXT* ctx);

void Threefish256_SetPrimitive(BLOCK_CIPHER* cipher);

/* Raw, stateless functions for external use in Skein. */
inline void Threefish256_KeySchedule(UINT256_64* key, uint64_t tweak[2], UINT256_64* subkeys);
inline void Threefish256_Forward_Raw(UINT256_64* block, UINT256_64* subkeys);
inline void Threefish256_Inverse_Raw(UINT256_64* block, UINT256_64* subkeys);

#ifdef __cplusplus
}
#endif

#endif
