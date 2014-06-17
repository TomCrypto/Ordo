/*===-- block_modes.c ---------------------------------*- generic -*- C -*-===*/

#include "ordo/primitives/block_modes.h"

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

/*===----------------------------------------------------------------------===*/

#if USING_ECB
#include "ordo/primitives/block_modes/ecb.h"
#endif
#if USING_CBC
#include "ordo/primitives/block_modes/cbc.h"
#endif
#if USING_CTR
#include "ordo/primitives/block_modes/ctr.h"
#endif
#if USING_CFB
#include "ordo/primitives/block_modes/cfb.h"
#endif
#if USING_OFB
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
        #if USING_ECB
        case BLOCK_MODE_ECB:
            return ecb_init(&state->jmp.ecb, cipher_state, iv, iv_len, direction, params);
        #endif
        #if USING_CBC
        case BLOCK_MODE_CBC:
            return cbc_init(&state->jmp.cbc, cipher_state, iv, iv_len, direction, params);
        #endif
        #if USING_CTR
        case BLOCK_MODE_CTR:
            return ctr_init(&state->jmp.ctr, cipher_state, iv, iv_len, direction, params);
        #endif
        #if USING_CFB
        case BLOCK_MODE_CFB:
            return cfb_init(&state->jmp.cfb, cipher_state, iv, iv_len, direction, params);
        #endif
        #if USING_OFB
        case BLOCK_MODE_OFB:
            return ofb_init(&state->jmp.ofb, cipher_state, iv, iv_len, direction, params);
        #endif
    }
    
    return ORDO_FAIL;
}

void block_mode_update(struct BLOCK_MODE_STATE *state,
                       struct BLOCK_STATE *cipher_state,
                       const void *in, size_t in_len,
                       void *out, size_t *out_len)
{
    switch (state->primitive)
    {
        #if USING_ECB
        case BLOCK_MODE_ECB:
            ecb_update(&state->jmp.ecb, cipher_state, in, in_len, out, out_len);
            break;
        #endif
        #if USING_CBC
        case BLOCK_MODE_CBC:
            cbc_update(&state->jmp.cbc, cipher_state, in, in_len, out, out_len);
            break;
        #endif
        #if USING_CTR
        case BLOCK_MODE_CTR:
            ctr_update(&state->jmp.ctr, cipher_state, in, in_len, out, out_len);
            break;
        #endif
        #if USING_CFB
        case BLOCK_MODE_CFB:
            cfb_update(&state->jmp.cfb, cipher_state, in, in_len, out, out_len);
            break;
        #endif
        #if USING_OFB
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
        #if USING_ECB
        case BLOCK_MODE_ECB:
            return ecb_final(&state->jmp.ecb, cipher_state, out, out_len);
        #endif
        #if USING_CBC
        case BLOCK_MODE_CBC:
            return cbc_final(&state->jmp.cbc, cipher_state, out, out_len);
        #endif
        #if USING_CTR
        case BLOCK_MODE_CTR:
            return ctr_final(&state->jmp.ctr, cipher_state, out, out_len);
        #endif
        #if USING_CFB
        case BLOCK_MODE_CFB:
            return cfb_final(&state->jmp.cfb, cipher_state, out, out_len);
        #endif
        #if USING_OFB
        case BLOCK_MODE_OFB:
            return ofb_final(&state->jmp.ofb, cipher_state, out, out_len);
        #endif
    }

    return ORDO_FAIL;
}

size_t block_mode_query(prim_t mode, prim_t cipher,
                        int query, size_t value)
{
    switch (mode)
    {
        #if USING_ECB
        case BLOCK_MODE_ECB:
            return ecb_query(cipher, query, value);
        #endif
        #if USING_CBC
        case BLOCK_MODE_CBC:
            return cbc_query(cipher, query, value);
        #endif
        #if USING_CTR
        case BLOCK_MODE_CTR:
            return ctr_query(cipher, query, value);
        #endif
        #if USING_CFB
        case BLOCK_MODE_CFB:
            return cfb_query(cipher, query, value);
        #endif
        #if USING_OFB
        case BLOCK_MODE_OFB:
            return ofb_query(cipher, query, value);
        #endif
    }
    
    return (size_t)-1;
}
