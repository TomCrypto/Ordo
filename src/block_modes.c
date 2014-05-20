/*===-- block_modes.c ---------------------------------*- generic -*- C -*-===*/

#include "ordo/primitives/block_modes.h"

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

/*===----------------------------------------------------------------------===*/

const char *block_mode_name(enum BLOCK_MODE mode)
{
    switch (mode)
    {
        case BLOCK_MODE_ECB:
            return "ECB";
        case BLOCK_MODE_CBC:
            return "CBC";
        case BLOCK_MODE_CTR:
            return "CTR";
        case BLOCK_MODE_CFB:
            return "CFB";
        case BLOCK_MODE_OFB:
            return "OFB";
    }

    return 0;
}

/*===----------------------------------------------------------------------===*/

enum BLOCK_MODE block_mode_by_name(const char *name)
{
    if (!strcmp(name, "ECB"))
        return BLOCK_MODE_ECB;
    if (!strcmp(name, "CBC"))
        return BLOCK_MODE_CBC;
    if (!strcmp(name, "CTR"))
        return BLOCK_MODE_CTR;
    if (!strcmp(name, "CFB"))
        return BLOCK_MODE_CFB;
    if (!strcmp(name, "OFB"))
        return BLOCK_MODE_OFB;

    return 0;
}

enum BLOCK_MODE block_mode_by_index(size_t index)
{
    switch (index)
    {
        case __COUNTER__: return BLOCK_MODE_ECB;
        case __COUNTER__: return BLOCK_MODE_CBC;
        case __COUNTER__: return BLOCK_MODE_CTR;
        case __COUNTER__: return BLOCK_MODE_CFB;
        case __COUNTER__: return BLOCK_MODE_OFB;
    }
    
    return 0;
}

size_t block_mode_count(void)
{
    return __COUNTER__;
}

/*===----------------------------------------------------------------------===*/

#include "ordo/primitives/block_modes/ecb.h"
#include "ordo/primitives/block_modes/cbc.h"
#include "ordo/primitives/block_modes/ctr.h"
#include "ordo/primitives/block_modes/cfb.h"
#include "ordo/primitives/block_modes/ofb.h"

int block_mode_init(struct BLOCK_MODE_STATE *state,
                    struct BLOCK_STATE *cipher_state,
                    const void *iv, size_t iv_len,
                    int direction,
                    enum BLOCK_MODE primitive,
                    const void *params)
{
    switch (state->primitive = primitive)
    {
        case BLOCK_MODE_ECB:
            return ecb_init(&state->jmp.ecb, cipher_state, iv, iv_len, direction, params);
        case BLOCK_MODE_CBC:
            return cbc_init(&state->jmp.cbc, cipher_state, iv, iv_len, direction, params);
        case BLOCK_MODE_CTR:
            return ctr_init(&state->jmp.ctr, cipher_state, iv, iv_len, direction, params);
        case BLOCK_MODE_CFB:
            return cfb_init(&state->jmp.cfb, cipher_state, iv, iv_len, direction, params);
        case BLOCK_MODE_OFB:
            return ofb_init(&state->jmp.ofb, cipher_state, iv, iv_len, direction, params);
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
        case BLOCK_MODE_ECB:
            ecb_update(&state->jmp.ecb, cipher_state, in, in_len, out, out_len);
            break;
        case BLOCK_MODE_CBC:
            cbc_update(&state->jmp.cbc, cipher_state, in, in_len, out, out_len);
            break;
        case BLOCK_MODE_CTR:
            ctr_update(&state->jmp.ctr, cipher_state, in, in_len, out, out_len);
            break;
        case BLOCK_MODE_CFB:
            cfb_update(&state->jmp.cfb, cipher_state, in, in_len, out, out_len);
            break;
        case BLOCK_MODE_OFB:
            ofb_update(&state->jmp.ofb, cipher_state, in, in_len, out, out_len);
            break;
    }
}

int block_mode_final(struct BLOCK_MODE_STATE *state,
                     struct BLOCK_STATE *cipher_state,
                     void *out, size_t *out_len)
{
    switch (state->primitive)
    {
        case BLOCK_MODE_ECB:
            return ecb_final(&state->jmp.ecb, cipher_state, out, out_len);
        case BLOCK_MODE_CBC:
            return cbc_final(&state->jmp.cbc, cipher_state, out, out_len);
        case BLOCK_MODE_CTR:
            return ctr_final(&state->jmp.ctr, cipher_state, out, out_len);
        case BLOCK_MODE_CFB:
            return cfb_final(&state->jmp.cfb, cipher_state, out, out_len);
        case BLOCK_MODE_OFB:
            return ofb_final(&state->jmp.ofb, cipher_state, out, out_len);
    }

    return ORDO_FAIL;
}

size_t block_mode_query(enum BLOCK_MODE mode,
                        enum BLOCK_CIPHER cipher,
                        int query, size_t value)
{
    switch (mode)
    {
        case BLOCK_MODE_ECB:
            return ecb_query(cipher, query, value);
        case BLOCK_MODE_CBC:
            return cbc_query(cipher, query, value);
        case BLOCK_MODE_CTR:
            return ctr_query(cipher, query, value);
        case BLOCK_MODE_CFB:
            return cfb_query(cipher, query, value);
        case BLOCK_MODE_OFB:
            return ofb_query(cipher, query, value);
    }
    
    return (size_t)-1;
}
