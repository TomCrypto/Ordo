/*===-- block_ciphers.c -------------------------------*- generic -*- C -*-===*/

#include "ordo/primitives/block_ciphers.h"

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

/*===----------------------------------------------------------------------===*/

const char *block_cipher_name(enum BLOCK_CIPHER primitive)
{
    switch (primitive)
    {
#ifdef USING_AES
        case BLOCK_AES:
            return "AES";
#endif
#ifdef USING_NULLCIPHER
        case BLOCK_NULLCIPHER:
            return "NullCipher";
#endif
#ifdef USING_THREEFISH256
        case BLOCK_THREEFISH256:
            return "Threefish-256";
#endif
    }

    return 0;
}

/*===----------------------------------------------------------------------===*/

enum BLOCK_CIPHER block_cipher_by_name(const char *name)
{
#ifdef USING_AES
    if (!strcmp(name, "AES"))
        return BLOCK_AES;
#endif
#ifdef USING_NULLCIPHER
    if (!strcmp(name, "NullCipher"))
        return BLOCK_NULLCIPHER;
#endif
#ifdef USING_THREEFISH256
    if (!strcmp(name, "Threefish-256"))
        return BLOCK_THREEFISH256;
#endif
    return 0;
}

enum BLOCK_CIPHER block_cipher_by_index(size_t index)
{
    switch (index)
    {
#ifdef USING_AES
        case __COUNTER__: return BLOCK_AES;
#endif
#ifdef USING_NULLCIPHER
        case __COUNTER__: return BLOCK_NULLCIPHER;
#endif
#ifdef USING_THREEFISH256
        case __COUNTER__: return BLOCK_THREEFISH256;
#endif
    }
    
    return 0;
}

size_t block_cipher_count(void)
{
    return __COUNTER__;
}

/*===----------------------------------------------------------------------===*/

#include "ordo/primitives/block_ciphers/aes.h"
#include "ordo/primitives/block_ciphers/nullcipher.h"
#include "ordo/primitives/block_ciphers/threefish256.h"

int block_cipher_init(struct BLOCK_STATE *state,
                      const void *key,
                      size_t key_len,
                      enum BLOCK_CIPHER primitive,
                      const void *params)
{
    switch (state->primitive = primitive)
    {
        case BLOCK_AES:
            return aes_init(&state->jmp.aes, key, key_len, params);
        case BLOCK_NULLCIPHER:
            return nullcipher_init(&state->jmp.nullcipher, key, key_len, params);
        case BLOCK_THREEFISH256:
            return threefish256_init(&state->jmp.threefish256, key, key_len, params);
    }
    
    return ORDO_FAIL;
}

void block_cipher_forward(const struct BLOCK_STATE *state,
                          void *block)
{
    switch (state->primitive)
    {
        case BLOCK_AES:
            aes_forward(&state->jmp.aes, block);
            break;
        case BLOCK_NULLCIPHER:
            nullcipher_forward(&state->jmp.nullcipher, block);
            break;
        case BLOCK_THREEFISH256:
            threefish256_forward(&state->jmp.threefish256, block);
            break;
    }
}

void block_cipher_inverse(const struct BLOCK_STATE *state,
                          void *block)
{
    switch (state->primitive)
    {
        case BLOCK_AES:
            aes_inverse(&state->jmp.aes, block);
            break;
        case BLOCK_NULLCIPHER:
            nullcipher_inverse(&state->jmp.nullcipher, block);
            break;
        case BLOCK_THREEFISH256:
            threefish256_inverse(&state->jmp.threefish256, block);
            break;
    }
}

void block_cipher_final(struct BLOCK_STATE *state)
{
    switch (state->primitive)
    {
        case BLOCK_AES:
            aes_final(&state->jmp.aes);
            break;
        case BLOCK_NULLCIPHER:
            nullcipher_final(&state->jmp.nullcipher);
            break;
        case BLOCK_THREEFISH256:
            threefish256_final(&state->jmp.threefish256);
            break;
    }
}

size_t block_cipher_query(enum BLOCK_CIPHER primitive,
                          int query, size_t value)
{
    switch (primitive)
    {
        case BLOCK_AES:
            return aes_query(query, value);
        case BLOCK_NULLCIPHER:
            return nullcipher_query(query, value);
        case BLOCK_THREEFISH256:
            return threefish256_query(query, value);
    }

    return (size_t)-1;
}
