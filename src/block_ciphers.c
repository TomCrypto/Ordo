/*===-- block_ciphers.c -------------------------------*- generic -*- C -*-===*/

#include "ordo/primitives/block_ciphers.h"

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

/*===----------------------------------------------------------------------===*/

typedef  int   (*BLOCK_INIT)
    (void *, const void *, size_t, const void *);
typedef void   (*BLOCK_UPDATE)
    (const void *, void *);
typedef void   (*BLOCK_FINAL)
    (void *);
typedef size_t (*BLOCK_QUERY)
    (int, size_t);

struct BLOCK_CIPHER
{
    BLOCK_INIT   init;
    BLOCK_UPDATE forward;
    BLOCK_UPDATE inverse;
    BLOCK_FINAL  final;
    BLOCK_QUERY  query;
    const char  *name;
};

/*===----------------------------------------------------------------------===*/

const char *block_cipher_name(const struct BLOCK_CIPHER *primitive)
{
    return primitive->name;
}

#include "ordo/primitives/block_ciphers/nullcipher.h"

const struct BLOCK_CIPHER *ordo_nullcipher(void)
{
    static const struct BLOCK_CIPHER primitive =
    {
        (BLOCK_INIT  )nullcipher_init,
        (BLOCK_UPDATE)nullcipher_forward,
        (BLOCK_UPDATE)nullcipher_inverse,
        (BLOCK_FINAL )nullcipher_final,
        (BLOCK_QUERY )nullcipher_query,
        "NullCipher"
    };

    return &primitive;
}

#include "ordo/primitives/block_ciphers/threefish256.h"

const struct BLOCK_CIPHER *ordo_threefish256(void)
{
    static const struct BLOCK_CIPHER primitive =
    {
        (BLOCK_INIT  )threefish256_init,
        (BLOCK_UPDATE)threefish256_forward,
        (BLOCK_UPDATE)threefish256_inverse,
        (BLOCK_FINAL )threefish256_final,
        (BLOCK_QUERY )threefish256_query,
        "Threefish-256"
    };

    return &primitive;
}

#include "ordo/primitives/block_ciphers/aes.h"

const struct BLOCK_CIPHER *ordo_aes(void)
{
    static const struct BLOCK_CIPHER primitive =
    {
        (BLOCK_INIT  )aes_init,
        (BLOCK_UPDATE)aes_forward,
        (BLOCK_UPDATE)aes_inverse,
        (BLOCK_FINAL )aes_final,
        (BLOCK_QUERY )aes_query,
        "AES"
    };

    return &primitive;
}

/*===----------------------------------------------------------------------===*/

const struct BLOCK_CIPHER *block_cipher_by_name(const char *name)
{
    size_t t;

    for (t = 0; t < block_cipher_count(); t++)
    {
        const struct BLOCK_CIPHER *primitive;
        primitive = block_cipher_by_index(t);

        if (!strcmp(name, primitive->name))
            return primitive;
    }

    return 0;
}

const struct BLOCK_CIPHER *block_cipher_by_index(size_t index)
{
    switch (index)
    {
        case __COUNTER__: return ordo_nullcipher();
        case __COUNTER__: return ordo_threefish256();
        case __COUNTER__: return ordo_aes();

        default: return 0;
    }
}

size_t block_cipher_count(void)
{
    return __COUNTER__;
}

/*===----------------------------------------------------------------------===*/

int block_cipher_init(const struct BLOCK_CIPHER *primitive,
                      void *state,
                      const void *key,
                      size_t key_len,
                      const void *params)
{
    return primitive->init(state, key, key_len, params);
}

void block_cipher_forward(const struct BLOCK_CIPHER *primitive,
                          const void *state,
                          void *block)
{
    primitive->forward(state, block);
}

void block_cipher_inverse(const struct BLOCK_CIPHER *primitive,
                          const void *state,
                          void *block)
{
    primitive->inverse(state, block);
}

void block_cipher_final(const struct BLOCK_CIPHER *primitive,
                        void *state)
{
    primitive->final(state);
}

size_t block_cipher_query(const struct BLOCK_CIPHER *primitive,
                          int query, size_t value)
{
    return primitive->query(query, value);
}
