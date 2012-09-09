#ifndef threefish256_h
#define threefish256_h

/**
 * @file threefish256.h
 *
 * \brief Threefish-256 block cipher interface.
 *
 * Threefish-256 is a block cipher, which has a 256-bit block size and a 256-bit key size. It also has an optional 128-bit tweak.
 * The tweak can be set through the cipher parameters.
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

void Threefish256_Create(CIPHER_PRIMITIVE_CONTEXT* cipher);

int Threefish256_Init(CIPHER_PRIMITIVE_CONTEXT* cipher, UINT256_64* key, size_t keySize, THREEFISH256_PARAMS* params);

void Threefish256_Forward(CIPHER_PRIMITIVE_CONTEXT* cipher, UINT256_64* block, size_t len);

void Threefish256_Inverse(CIPHER_PRIMITIVE_CONTEXT* cipher, UINT256_64* block, size_t len);

void Threefish256_Free(CIPHER_PRIMITIVE_CONTEXT* cipher);

void Threefish256_SetPrimitive(CIPHER_PRIMITIVE* primitive);

#endif