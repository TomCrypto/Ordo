#include <primitives/stream_ciphers/rc4.h>

#include <internal/asm/resolve.h>
#include <common/errors.h>
#include <common/utils.h>
#include <internal/mem.h>

#include <string.h>

/******************************************************************************/

#if !defined(RC4_STANDARD)
void rc4_update_ASM(void *state, size_t len, void *in, void *out);
#endif

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

struct RC4_STATE* rc4_alloc(void)
{
    return mem_alloc(sizeof(struct RC4_STATE));
}

int rc4_init(struct RC4_STATE *state,
             const uint8_t *key,
             size_t key_len,
             const struct RC4_PARAMS *params)
{
    size_t t, drop;
    uint8_t tmp;

    if ((key_len < bits(40)) || (key_len > bits(2048))) return ORDO_KEY_LEN;

    for (t = 0; t < 256; t++) state->s[t] = t;

    state->j = 0;
    for (t = 0; t < 256; t++)
    {
        state->j = (state->j + state->s[t] + key[t % key_len]);
        state->j &= 0xFF; /* For the 64-bit version. */

        tmp = state->s[t];
        state->s[t] = state->s[state->j];
        state->s[state->j] = tmp;
    }

    state->i = 0;
    state->j = 0;

    /* We need to drop 2048 bytes by default. */
    drop = (params == 0) ? 2048 : params->drop;

    for (t = 0; t < drop; t++) rc4_update(state, &tmp, 1);

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
    mem_free(state);
}

size_t rc4_key_len(size_t key_len)
{
    if (key_len < bits(40))   return bits(40);
    if (key_len > bits(2048)) return bits(2048);
    return key_len;
}

void rc4_copy(struct RC4_STATE *dst, const struct RC4_STATE *src)
{
    memcpy(dst, src, sizeof(struct RC4_STATE));
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
