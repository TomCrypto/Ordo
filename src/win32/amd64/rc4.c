/*===-- rc4.c -------------------------------------*- win32/amd64 -*- C -*-===*/

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

#include "ordo/primitives/stream_ciphers/rc4.h"

/*===----------------------------------------------------------------------===*/

#define RC4_DROP_DEFAULT 2048

static void rc4_key_schedule(struct RC4_STATE *state, unsigned drop,
                             const uint8_t *key, size_t key_len) HOT_CODE;

extern void rc4_update_ASM(void *state, uint64_t len, void *in, void *out);

#ifdef OPAQUE
struct RC4_STATE
{
    uint64_t i, j;
    uint64_t s[256];
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
    rc4_update_ASM(state, len, buffer, buffer);
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
        state->j = (uint8_t)(state->j + state->s[t] + key[t % key_len]);
        pswap64(&state->s[t], &state->s[state->j]);
    }

    state->j = 0;

    while (drop--) rc4_update(state, &tmp, sizeof(uint8_t));
}
