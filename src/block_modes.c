/*===-- block_modes.c ---------------------------------*- generic -*- C -*-===*/

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

#include "ordo/primitives/block_modes.h"

/*===----------------------------------------------------------------------===*/

#if WITH_ECB
#include "ordo/primitives/block_modes/ecb.h"
#endif
#if WITH_CBC
#include "ordo/primitives/block_modes/cbc.h"
#endif
#if WITH_CTR
#include "ordo/primitives/block_modes/ctr.h"
#endif
#if WITH_CFB
#include "ordo/primitives/block_modes/cfb.h"
#endif
#if WITH_OFB
#include "ordo/primitives/block_modes/ofb.h"
#endif

int block_mode_init(struct BLOCK_MODE_STATE *state,
                    struct BLOCK_STATE *cipher_state,
                    const void *iv, size_t iv_len,
                    int direction,
                    prim_t primitive, const void *params)
{
    switch (state->primitive = primitive)
    {
        #if WITH_ECB
        case BLOCK_MODE_ECB:
            return ecb_init(&state->jmp.ecb, cipher_state, iv, iv_len, direction, params);
        #endif
        #if WITH_CBC
        case BLOCK_MODE_CBC:
            return cbc_init(&state->jmp.cbc, cipher_state, iv, iv_len, direction, params);
        #endif
        #if WITH_CTR
        case BLOCK_MODE_CTR:
            return ctr_init(&state->jmp.ctr, cipher_state, iv, iv_len, direction, params);
        #endif
        #if WITH_CFB
        case BLOCK_MODE_CFB:
            return cfb_init(&state->jmp.cfb, cipher_state, iv, iv_len, direction, params);
        #endif
        #if WITH_OFB
        case BLOCK_MODE_OFB:
            return ofb_init(&state->jmp.ofb, cipher_state, iv, iv_len, direction, params);
        #endif
    }

    return ORDO_ARG;
}

void block_mode_update(struct BLOCK_MODE_STATE *state,
                       struct BLOCK_STATE *cipher_state,
                       const void *in, size_t in_len,
                       void *out, size_t *out_len)
{
    switch (state->primitive)
    {
        #if WITH_ECB
        case BLOCK_MODE_ECB:
            ecb_update(&state->jmp.ecb, cipher_state, in, in_len, out, out_len);
            break;
        #endif
        #if WITH_CBC
        case BLOCK_MODE_CBC:
            cbc_update(&state->jmp.cbc, cipher_state, in, in_len, out, out_len);
            break;
        #endif
        #if WITH_CTR
        case BLOCK_MODE_CTR:
            ctr_update(&state->jmp.ctr, cipher_state, in, in_len, out, out_len);
            break;
        #endif
        #if WITH_CFB
        case BLOCK_MODE_CFB:
            cfb_update(&state->jmp.cfb, cipher_state, in, in_len, out, out_len);
            break;
        #endif
        #if WITH_OFB
        case BLOCK_MODE_OFB:
            ofb_update(&state->jmp.ofb, cipher_state, in, in_len, out, out_len);
            break;
        #endif
    }
}

int block_mode_final(struct BLOCK_MODE_STATE *state,
                     struct BLOCK_STATE *cipher_state,
                     void *out, size_t *out_len)
{
    switch (state->primitive)
    {
        #if WITH_ECB
        case BLOCK_MODE_ECB:
            return ecb_final(&state->jmp.ecb, cipher_state, out, out_len);
        #endif
        #if WITH_CBC
        case BLOCK_MODE_CBC:
            return cbc_final(&state->jmp.cbc, cipher_state, out, out_len);
        #endif
        #if WITH_CTR
        case BLOCK_MODE_CTR:
            return ctr_final(&state->jmp.ctr, cipher_state, out, out_len);
        #endif
        #if WITH_CFB
        case BLOCK_MODE_CFB:
            return cfb_final(&state->jmp.cfb, cipher_state, out, out_len);
        #endif
        #if WITH_OFB
        case BLOCK_MODE_OFB:
            return ofb_final(&state->jmp.ofb, cipher_state, out, out_len);
        #endif
    }

    return ORDO_ARG;
}

int block_mode_limits(prim_t mode, prim_t cipher,
                      struct BLOCK_MODE_LIMITS *limits)
{
    switch (mode)
    {
        #if WITH_ECB
        case BLOCK_MODE_ECB:
            return ecb_limits(cipher, limits);
        #endif
        #if WITH_CBC
        case BLOCK_MODE_CBC:
            return cbc_limits(cipher, limits);
        #endif
        #if WITH_CTR
        case BLOCK_MODE_CTR:
            return ctr_limits(cipher, limits);
        #endif
        #if WITH_CFB
        case BLOCK_MODE_CFB:
            return cfb_limits(cipher, limits);
        #endif
        #if WITH_OFB
        case BLOCK_MODE_OFB:
            return ofb_limits(cipher, limits);
        #endif
    }

    return ORDO_ARG;
}
