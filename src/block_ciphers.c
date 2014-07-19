/*===-- block_ciphers.c -------------------------------*- generic -*- C -*-===*/

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

#include "ordo/primitives/block_ciphers.h"

/*===----------------------------------------------------------------------===*/

#if WITH_AES
#include "ordo/primitives/block_ciphers/aes.h"
#endif
#if WITH_NULLCIPHER
#include "ordo/primitives/block_ciphers/nullcipher.h"
#endif
#if WITH_THREEFISH256
#include "ordo/primitives/block_ciphers/threefish256.h"
#endif

int block_init(struct BLOCK_STATE *state,
               const void *key, size_t key_len,
               prim_t primitive, const void *params)
{
    switch (state->primitive = primitive)
    {
        #if WITH_AES
        case BLOCK_AES:
            return aes_init(&state->jmp.aes, key, key_len, params);
        #endif
        #if WITH_NULLCIPHER
        case BLOCK_NULLCIPHER:
            return nullcipher_init(&state->jmp.nullcipher, key, key_len, params);
        #endif
        #if WITH_THREEFISH256
        case BLOCK_THREEFISH256:
            return threefish256_init(&state->jmp.threefish256, key, key_len, params);
        #endif
    }
    
    return ORDO_FAIL;
}

void block_forward(const struct BLOCK_STATE *state,
                   void *block)
{
    switch (state->primitive)
    {
        #if WITH_AES
        case BLOCK_AES:
            aes_forward(&state->jmp.aes, block);
            break;
        #endif
        #if WITH_NULLCIPHER
        case BLOCK_NULLCIPHER:
            nullcipher_forward(&state->jmp.nullcipher, block);
            break;
        #endif
        #if WITH_THREEFISH256
        case BLOCK_THREEFISH256:
            threefish256_forward(&state->jmp.threefish256, block);
            break;
        #endif
    }
}

void block_inverse(const struct BLOCK_STATE *state,
                   void *block)
{
    switch (state->primitive)
    {
        #if WITH_AES
        case BLOCK_AES:
            aes_inverse(&state->jmp.aes, block);
            break;
        #endif
        #if WITH_NULLCIPHER
        case BLOCK_NULLCIPHER:
            nullcipher_inverse(&state->jmp.nullcipher, block);
            break;
        #endif
        #if WITH_THREEFISH256
        case BLOCK_THREEFISH256:
            threefish256_inverse(&state->jmp.threefish256, block);
            break;
        #endif
    }
}

void block_final(struct BLOCK_STATE *state)
{
    switch (state->primitive)
    {
        #if WITH_AES
        case BLOCK_AES:
            aes_final(&state->jmp.aes);
            break;
        #endif
        #if WITH_NULLCIPHER
        case BLOCK_NULLCIPHER:
            nullcipher_final(&state->jmp.nullcipher);
            break;
        #endif
        #if WITH_THREEFISH256
        case BLOCK_THREEFISH256:
            threefish256_final(&state->jmp.threefish256);
            break;
        #endif
    }
}

size_t block_query(prim_t primitive,
                   int query, size_t value)
{
    switch (primitive)
    {
        #if WITH_AES
        case BLOCK_AES:
            return aes_query(query, value);
        #endif
        #if WITH_NULLCIPHER
        case BLOCK_NULLCIPHER:
            return nullcipher_query(query, value);
        #endif
        #if WITH_THREEFISH256
        case BLOCK_THREEFISH256:
            return threefish256_query(query, value);
        #endif
    }

    return (size_t)-1;
}

size_t block_bsize(void)
{
    return sizeof(struct BLOCK_STATE);
}
