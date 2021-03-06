/*===-- rc4.c -----------------------------------------*- generic -*- C -*-===*/

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

#include "ordo/primitives/stream_ciphers/rc4.h"

/*===----------------------------------------------------------------------===*/

#define RC4_DROP_DEFAULT 2048

static void rc4_key_schedule(struct RC4_STATE *state, unsigned drop,
                             const uint8_t *key, size_t key_len) HOT_CODE;
static uint8_t rc4_next(struct RC4_STATE *state) HOT_CODE;

#ifdef OPAQUE
struct RC4_STATE
{
    uint8_t i;
    uint8_t j;
    uint8_t s[256];
};
#endif

/*===----------------------------------------------------------------------===*/

int rc4_init(struct RC4_STATE *state,
             const void *key, size_t key_len,
             const struct RC4_PARAMS *params)
{
    if ((key_len < bits(40)) || (key_len > bits(2048))) return ORDO_KEY_LEN;
    rc4_key_schedule(state, (params == 0) ? RC4_DROP_DEFAULT : params->drop,
                     (uint8_t *)key, key_len);

    return ORDO_SUCCESS;
}

void rc4_update(struct RC4_STATE *state,
                void *buffer, size_t len)
{
    uint8_t *bytes = (uint8_t *)buffer;

    while (len--) *(bytes++) ^= rc4_next(state);
}

void rc4_final(struct RC4_STATE *state)
{
    return;
}

/*===----------------------------------------------------------------------===*/

void rc4_key_schedule(struct RC4_STATE *state, unsigned drop,
                      const uint8_t *key, size_t key_len)
{
    uint8_t tmp;
    unsigned t;

    state->i = 0;
    state->j = 0;

    for (t = 0; t < 256; ++t) state->s[t] = (uint8_t)t;
    for (t = 0; t < 256; ++t)
    {
        state->j = state->j + state->s[t] + key[t % key_len];
        pswap8(state->s + t, state->s + state->j);
    }

    state->j = 0;

    while (drop--) rc4_update(state, &tmp, sizeof(uint8_t));
}

uint8_t rc4_next(struct RC4_STATE *state)
{
    state->j += state->s[++state->i];
    pswap8(state->s + state->i, state->s + state->j);
    return state->s[(state->s[state->i] + state->s[state->j]) & 0xFF];
}
