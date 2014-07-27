/*===-- nullcipher.c ----------------------------------*- generic -*- C -*-===*/

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

#include "ordo/primitives/block_ciphers/nullcipher.h"

/*===----------------------------------------------------------------------===*/

#ifdef OPAQUE
struct NULLCIPHER_STATE
{
    unsigned char dummy;
};
#endif

/*===----------------------------------------------------------------------===*/

int nullcipher_init(struct NULLCIPHER_STATE *state,
                    const void *key, size_t key_len,
                    const void *params)
{
    if (!limit_check(key_len, bits(0), bits(0), 1))
        return ORDO_KEY_LEN;

    state->dummy = 0x42;
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
