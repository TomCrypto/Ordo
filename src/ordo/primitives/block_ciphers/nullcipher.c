#include "ordo/primitives/block_ciphers/nullcipher.h"

#include "ordo/internal/mem.h"
#include "ordo/common/utils.h"

/******************************************************************************/

#define NULLCIPHER_BLOCK (bits(128)) /* This is arbitrary. */

struct NULLCIPHER_STATE
{
    uint8_t dummy;
};

struct NULLCIPHER_STATE * ORDO_CALLCONV
nullcipher_alloc(void)
{
    /* A block cipher always needs to allocate a state (returning nil means
       an allocation failed, so we can't use that even for this cipher). */
    return mem_alloc(sizeof(struct NULLCIPHER_STATE));
}

int ORDO_CALLCONV
nullcipher_init(struct NULLCIPHER_STATE *state,
                const void *key, size_t key_len,
                const void *params)
{
    if (nullcipher_query(KEY_LEN, key_len) != key_len)
    {
        return ORDO_KEY_LEN;
    }

    state->dummy = 42;
    return ORDO_SUCCESS;
}

void ORDO_CALLCONV
nullcipher_forward(struct NULLCIPHER_STATE *state, void *block)
{
    return;
}

void ORDO_CALLCONV
nullcipher_inverse(struct NULLCIPHER_STATE *state, void *block)
{
    return;
}

void ORDO_CALLCONV
nullcipher_free(struct NULLCIPHER_STATE *state)
{
    mem_free(state);
}

void ORDO_CALLCONV
nullcipher_copy(struct NULLCIPHER_STATE *dst,
                const struct NULLCIPHER_STATE *src)
{
    dst->dummy = src->dummy; /* Example. */
}

size_t ORDO_CALLCONV
nullcipher_query(int query, size_t value)
{
    switch(query)
    {
        case BLOCK_SIZE: return NULLCIPHER_BLOCK;

        case KEY_LEN: return 0;

        default: return 0;
    }
}
