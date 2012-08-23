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

#define RC4_KEY (sizeof(RC4STATE))
#define RC4_BLOCK (64 / 8) // 64-bit block
#define RC4_TWEAK 0 // no tweak

int RC4_KeyCheck(size_t keySize)
{
    /* Allowed keys are 40-2048 bits long. */
    return ((keySize >= 5) && (keySize <= 256));
}

/* Swaps two bytes. */
void swapByte(unsigned char* a, unsigned char* b)
{
    unsigned char c;
    c = *a;
    *a = *b;
    *b = c;
}

/* RC4 forward permutation function. */
void RC4_Forward(unsigned char* output, RC4STATE* state)
{
    /* Loop variable. */
    size_t t;

    /* Update the state for each output byte. */
    for (t = 0; t < RC4_BLOCK; t++)
    {
        state->i++;
        state->j += state->s[state->i];
        swapByte(&state->s[state->i], &state->s[state->j]);
        if (output != 0)
        {
            /* This is to allow optional output (for dropping bytes for instance). */
            *output = state->s[(state->s[state->i] + state->s[state->j]) % 256];
            output++;
        }
    }
}

/* RC4 key schedule. */
void RC4_KeySchedule(unsigned char* rawKey, size_t len, void* unused, RC4STATE* state, RC4_PARAMS* params)
{
    /* Loop variables. */
    size_t t, drop;

    /* Initialize the permutation array. */
    for (t = 0; t < 256; t++)
    {
        state->s[t] = t;
        //memcpy(&state->s[t], &t, 1); // Jesus, MinGW optimization is... buggy to say the least
    }

    /* Prepare the swap. */
    state->j = 0;
    for (t = 0; t < 256; t++)
    {
        state->j += state->s[t] + rawKey[t % len];
        swapByte(&state->s[t], &state->s[state->j]);
    }

    /* Reset the state pointers. */
    state->i = 0;
    state->j = 0;

    /* Calculate the amount of bytes to drop (default is 2048). */
    drop = (params == 0) ? 2048 : params->drop;

    /* Throw away the first drop bytes. */
    for (t = 0; t < drop; t++) RC4_Forward(0, state);
}

/* Fills a CIPHER_PRIMITIVE struct with the correct information. */
void RC4_SetPrimitive(CIPHER_PRIMITIVE* primitive)
{
    PRIMITIVE_MAKECIPHER(primitive, RC4_KEY, RC4_BLOCK, RC4_TWEAK, RC4_KeyCheck, RC4_KeySchedule, RC4_Forward, 0, "RC4");
}
