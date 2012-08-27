/**
 * @file rc4.c
 * Implements the RC4 cipher primitive.
 *
 * RC4 is a stream cipher, which has a 8-byte "block size" (for optimizations, in reality it outputs one byte at a time) and a key size between
 * 40 and 2048 bits (multiples of 8 bits only). It uses no tweak. The reason for the 8-byte block size is that state updates can be cached and
 * quickly combined with the plaintext, instead of taking one byte at a time, which would incur severe overhead.
 * Note this implementation of RC4 drops the first 2048 bytes of the keystream by default for security reasons, the drop amount can be changed
 * upon key schedule via the params parameter (a pointer to an RC4_PARAMS struct which contains a drop field to select the amount to drop.
 *
 * @see rc4.h
 */

#include <primitives/primitives.h>
#include <primitives/ciphers/rc4.h>

#define RC4_BLOCK (4096 / 8) // 64-bit block

/* Swaps two bytes. */
void swapByte(uint8_t* a, uint8_t* b)
{
    uint8_t c;
    c = *a;
    *a = *b;
    *b = c;
}

/* A structure containing an RC4 state. */
typedef struct RC4_STATE
{
    uint8_t s[256];
    uint8_t i;
    uint8_t j;
} RC4_STATE;

/* Shorthand macro for context casting. */
#define state(x) ((RC4_STATE*)(x->cipher))

void RC4_Create(CIPHER_PRIMITIVE_CONTEXT* cipher)
{
    /* Allocate memory for the RC4 state. */
    cipher->cipher = salloc(sizeof(RC4_STATE));
}

int RC4_Init(CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* key, size_t keySize, RC4_PARAMS* params)
{
    /* Loop variables. */
    size_t t, drop;
    uint8_t tmp;

    /* Allowed keys are 40-2048 bits long. */
    if ((keySize < 5) || (keySize > 256)) return ORDO_EKEYSIZE;

    /* Initialize the permutation array. */
    for (t = 0; t < 256; t++) state(cipher)->s[t] = t;

    /* Prepare the swap. */
    state(cipher)->j = 0;
    for (t = 0; t < 256; t++)
    {
        state(cipher)->j += state(cipher)->s[t] + key[t % keySize];
        swapByte(&state(cipher)->s[t], &state(cipher)->s[state(cipher)->j]);
    }

    /* Reset the state pointers. */
    state(cipher)->i = 0;
    state(cipher)->j = 0;

    /* Calculate the amount of bytes to drop (default is 2048). */
    drop = (params == 0) ? 2048 : params->drop;

    /* Throw away the first drop bytes (divide by block size since permutation function generates that much). */
    for (t = 0; t < drop; t++) RC4_Update(cipher, &tmp, 1);

    /* Return success. */
    return ORDO_ESUCCESS;
}

void RC4_Update(CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* block, size_t len)
{
    /* Loop variable. */
    RC4_STATE state = *(RC4_STATE*)cipher->cipher;
    size_t t = 0;

    /* Iterate over each byte and xor the keystream with the plaintext. */
    while (t != len)
    {
        state.j += state.s[++state.i];
        swapByte(&state.s[state.i], &state.s[state.j]);
        block[t++] ^= state.s[(state.s[state.i] + state.s[state.j]) & 0xFF];
    }

    /* Copy the state back in. */
    *(RC4_STATE*)cipher->cipher = state;
}

void RC4_Free(CIPHER_PRIMITIVE_CONTEXT* cipher)
{
    /* Free memory for the RC4 state. */
    sfree(cipher->cipher, sizeof(RC4_STATE));
}

/* Fills a CIPHER_PRIMITIVE struct with the correct information. */
void RC4_SetPrimitive(CIPHER_PRIMITIVE* primitive)
{
    PRIMITIVE_MAKECIPHER(primitive, RC4_BLOCK, RC4_Create, RC4_Init, RC4_Update, 0, RC4_Free, "RC4");
}
