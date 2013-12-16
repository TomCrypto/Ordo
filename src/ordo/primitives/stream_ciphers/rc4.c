#include "ordo/primitives/stream_ciphers/rc4.h"

#include "ordo/internal/environment.h"
#include "ordo/internal/asm/resolve.h"

#include "ordo/internal/mem.h"
#include "ordo/common/utils.h"

#include <string.h>

/******************************************************************************/

#define RC4_DROP_DEFAULT 2048

#if defined(RC4_X86_64_LINUX) || defined(RC4_X86_64_WINDOWS)

struct RC4_STATE
{
    uint64_t i;
    uint64_t j;
    uint64_t s[256];
};

void rc4_update_ASM(void *state, uint64_t len, void *in, void *out);

#elif defined(RC4_STANDARD)

struct RC4_STATE
{
    uint8_t s[256];
    uint8_t i;
    uint8_t j;
};
    
static void ORDO_CALLCONV
swap_byte(uint8_t* a, uint8_t* b)
{
    uint8_t c = *a;
    *a = *b;
    *b = c;
}

static uint8_t ORDO_CALLCONV
rc4_next(struct RC4_STATE *state)
ORDO_HOT_CODE;

uint8_t ORDO_CALLCONV
rc4_next(struct RC4_STATE *state)
{
    state->j += state->s[++state->i];
    swap_byte(&state->s[state->i], &state->s[state->j]);
    return state->s[(uint8_t)(state->s[state->i] + state->s[state->j])];
}

#endif

/******************************************************************************/

struct RC4_STATE * ORDO_CALLCONV
rc4_alloc(void)
{
    return mem_alloc(sizeof(struct RC4_STATE));
}

int ORDO_CALLCONV
rc4_init(struct RC4_STATE *state,
         const uint8_t *key, size_t key_len,
         const struct RC4_PARAMS *params)
{
    uint8_t t = 0;
    uint8_t tmp;

    if ((key_len < bits(40)) || (key_len > bits(2048))) return ORDO_KEY_LEN;

    state->i = 0;
    state->j = 0;

    /* Prepare permutation table. */
    do state->s[t] = t; while (++t);
    
    do
    {
        state->j = (uint8_t)(state->j + state->s[t] + key[t % key_len]);

        /* Can't use the specialized byte swap here, since this is general code
         * where those integers might be of a different type than a uint8_t. */
        tmp = (uint8_t)state->s[t];
        state->s[t] = state->s[state->j];
        state->s[state->j] = tmp;
    } while (++t);

    state->j = 0;

    {
        size_t drop = (params == 0) ? RC4_DROP_DEFAULT : params->drop;
        while (drop--) rc4_update(state, &tmp, sizeof(uint8_t));
        mem_erase(&tmp, sizeof(uint8_t));
    }

    return ORDO_SUCCESS;
}

void ORDO_CALLCONV
rc4_update(struct RC4_STATE *state,
           uint8_t *buffer, size_t len)
{
    #if defined(RC4_X86_64_LINUX) || defined(RC4_X86_64_WINDOWS)

    rc4_update_ASM(state, len, buffer, buffer);

    #elif defined(RC4_STANDARD)

    while (len--) *(buffer++) ^= rc4_next(state);

    #endif
}

void ORDO_CALLCONV
rc4_free(struct RC4_STATE *state)
{
    mem_free(state);
}

size_t ORDO_CALLCONV
rc4_query(int query, size_t key_len)
{
    switch (query)
    {
        case KEY_LEN:
        {
            if (key_len < bits(40))   return bits(40);
            if (key_len > bits(2048)) return bits(2048);
            return key_len;
        }
        
        default: return 0;
    }
}

void ORDO_CALLCONV
rc4_copy(struct RC4_STATE *dst,
         const struct RC4_STATE *src)
{
    memcpy(dst, src, sizeof(struct RC4_STATE));
}
