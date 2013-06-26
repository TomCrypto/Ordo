#include <primitives/stream_ciphers/rc4.h>

#include <internal/asm/resolve.h>
#include <common/ordo_errors.h>
#include <common/secure_mem.h>

#include <string.h>

/******************************************************************************/

/* A structure containing an RC4 state. */
struct RC4_STATE
{
#if defined (RC4_X86_64_LINUX) || defined (RC4_X86_64_WINDOWS)
    uint64_t i;
    uint64_t j;
    uint64_t s[256];
#elif defined (RC4_STANDARD)
    uint8_t s[256];
    uint8_t i;
    uint8_t j;
#endif
};

/* Swaps two bytes. */
void swap_byte(uint8_t* a, uint8_t* b)
{
    uint8_t c;
    c = *a;
    *a = *b;
    *b = c;
}

struct RC4_STATE* rc4_alloc()
{
    return secure_alloc(sizeof(struct RC4_STATE));
}

int rc4_init(struct RC4_STATE *state, const uint8_t* key, size_t keySize,
             const struct RC4_PARAMS* params)
{
    /* Loop variables. */
    size_t t, drop;
    uint8_t tmp;

    /* Allowed keys are 40-2048 bits long. */
    if ((keySize < 5) || (keySize > 256)) return ORDO_KEY_SIZE;

    /* Initialize the permutation array. */
    for (t = 0; t < 256; t++) state->s[t] = t;

    /* Mix the key into the RC4 state. */
    state->j = 0;
    for (t = 0; t < 256; t++)
    {
        /* Update state pointer. */
        state->j = (state->j + state->s[t] + key[t % keySize]);
        state->j &= 0xFF; /* For the 64-bit version. */

        /* Swap. */
        tmp = state->s[t];
        state->s[t] = state->s[state->j];
        state->s[state->j] = tmp;
    }

    /* Reset the state pointers. */
    state->i = 0;
    state->j = 0;

    /* Calculate the amount of bytes to drop (default is 2048). */
    drop = (params == 0) ? 2048 : params->drop;

    /* Throw away the first drop bytes. */
    for (t = 0; t < drop; t++) rc4_update(state, &tmp, 1);

    /* Return success. */
    return ORDO_SUCCESS;
}

void rc4_update(struct RC4_STATE *state, uint8_t* buffer, size_t len)
{
    #if defined (RC4_X86_64_LINUX) || defined (RC4_X86_64_WINDOWS)
    /* Fast 64-bit implementation (note in 64-bit mode, len is a 64-bit
     * unsigned integer). */
    rc4_update_ASM(state, len, buffer, buffer);
    #elif defined (RC4_STANDARD)
    size_t t = 0;

    /* Iterate over each byte and xor the keystream with the plaintext. */
    while (t != len)
    {
        state->j += state->s[++state->i];
        swap_byte(&state->s[state->i], &state->s[state->j]);
        buffer[t++] ^= state->s[(uint8_t)(state->s[state->i] + state->s[state->j])];
    }
    #endif
}

void rc4_free(struct RC4_STATE *state)
{
    secure_free(state, sizeof(struct RC4_STATE));
}

void rc4_copy(struct RC4_STATE *dst, const struct RC4_STATE *src)
{
    memcpy(dst, src, sizeof(struct RC4_STATE));
}

size_t rc4_key_len(size_t key_len)
{
    if (key_len < 5) return 5;
    if (key_len > 256) return 256;
    return key_len;
}

void rc4_set_primitive(struct STREAM_CIPHER* cipher)
{
    make_stream_cipher(cipher,
                       (STREAM_ALLOC)rc4_alloc,
                       (STREAM_INIT)rc4_init,
                       (STREAM_UPDATE)rc4_update,
                       (STREAM_FREE)rc4_free,
                       (STREAM_COPY)rc4_copy,
                       (STREAM_KEYLEN)rc4_key_len,
                       "RC4");
}
