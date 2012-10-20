#ifndef AES_H
#define AES_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file aes.h
 *
 * \brief AES block cipher.
 *
 * AES (Advanced Encryption Standard) is a block cipher, which has a 128-bit block size and three
 * possible key sizes, namely 128, 192 or 256 bytes. It is based on Rijndael cipher and was
 * selected as the official encryption standard in November 2001 (FIPS 197).
 *
 * @see aes.c
 */

#include <primitives/primitives.h>

/*! \brief AES cipher parameters.
 *
 * A parameter structure for AES - allows to change the number of rounds. */
typedef struct AES_PARAMS
{
    /*! The number of rounds to use. The defaults are 10 for a 128-bit key, 12 for a 192-bit key,
     * and 14 for a 256-bit key, and are standard. It is strongly discouraged to lower the number
     * of rounds below the default values. */
    size_t rounds;
} AES_PARAMS;

BLOCK_CIPHER_CONTEXT* AES_Create();

int AES_Init(BLOCK_CIPHER_CONTEXT* ctx, void* key, size_t keySize, AES_PARAMS* params);

void AES_Forward(BLOCK_CIPHER_CONTEXT* ctx, uint8_t* block);

void AES_Inverse(BLOCK_CIPHER_CONTEXT* ctx, uint8_t* block);

void AES_Free(BLOCK_CIPHER_CONTEXT* ctx);

void AES_SetPrimitive(BLOCK_CIPHER* cipher);

#ifdef __cplusplus
}
#endif

#endif
