//===-- nullcipher.c ----------------------------------*- generic -*- C -*-===//

#include "ordo/primitives/block_ciphers/nullcipher.h"

/// @cond
#include "ordo/internal/implementation.h"
/// @endcond

//===----------------------------------------------------------------------===//

#define NULLCIPHER_BLOCK (bits(128)) // This is arbitrary.

struct NULLCIPHER_STATE
{
    uint8_t dummy;
};

struct NULLCIPHER_STATE *nullcipher_alloc(void)
{
    // A block cipher always needs to allocate a state (returning nil means
    // an allocation failed, so we can't use that even for this cipher).
    return mem_alloc(sizeof(struct NULLCIPHER_STATE));
}

int nullcipher_init(struct NULLCIPHER_STATE *state,
                    const void *key, size_t key_len,
                    const void *params)
{
    if (nullcipher_query(KEY_LEN_Q, key_len) != key_len) return ORDO_KEY_LEN;

    state->dummy = 42;
    return ORDO_SUCCESS;
}

void nullcipher_forward(const struct NULLCIPHER_STATE *state, void *block)
{
    return;
}

void nullcipher_inverse(const struct NULLCIPHER_STATE *state, void *block)
{
    return;
}

void nullcipher_final(struct NULLCIPHER_STATE *state)
{
    return;
}

void nullcipher_free(struct NULLCIPHER_STATE *state)
{
    mem_free(state);
}

void nullcipher_copy(struct NULLCIPHER_STATE *dst,
                     const struct NULLCIPHER_STATE *src)
{
    dst->dummy = src->dummy; // For example
}

size_t nullcipher_query(int query, size_t value)
{
    switch(query)
    {
        case BLOCK_SIZE_Q: return NULLCIPHER_BLOCK;
        case KEY_LEN_Q   : return 0;
        default          : return 0;
    }
}
