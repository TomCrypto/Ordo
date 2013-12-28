//===-- block_ciphers.c -------------------------------*- generic -*- C -*-===//

#include "ordo/primitives/block_ciphers.h"

/// @cond
#include "ordo/internal/implementation.h"
/// @endcond

//===----------------------------------------------------------------------===//

typedef void  *(*BLOCK_ALLOC)
    (void);
typedef  int   (*BLOCK_INIT)
    (void *, const void *, size_t, const void *);
typedef void   (*BLOCK_UPDATE)
    (const void *, void *);
typedef void   (*BLOCK_FINAL)
    (void *);
typedef void   (*BLOCK_FREE)
    (void *);
typedef void   (*BLOCK_COPY)
    (void *, const void *);
typedef size_t (*BLOCK_QUERY)
    (int, size_t);

struct BLOCK_CIPHER
{
    BLOCK_ALLOC  alloc;
    BLOCK_INIT   init;
    BLOCK_UPDATE forward;
    BLOCK_UPDATE inverse;
    BLOCK_FINAL  final;
    BLOCK_FREE   free;
    BLOCK_COPY   copy;
    BLOCK_QUERY  query;
    const char  *name;
};

//===----------------------------------------------------------------------===//

const char *block_cipher_name(const struct BLOCK_CIPHER *primitive)
{
    return primitive->name;
}

#include "ordo/primitives/block_ciphers/nullcipher.h"
#include "ordo/primitives/block_ciphers/threefish256.h"
#include "ordo/primitives/block_ciphers/aes.h"

static struct BLOCK_CIPHER primitives[] =
{
    #define INDEX_NULLCIPHER 0
    {
        (BLOCK_ALLOC )nullcipher_alloc,
        (BLOCK_INIT  )nullcipher_init,
        (BLOCK_UPDATE)nullcipher_forward,
        (BLOCK_UPDATE)nullcipher_inverse,
        (BLOCK_FINAL )nullcipher_final,
        (BLOCK_FREE  )nullcipher_free,
        (BLOCK_COPY  )nullcipher_copy,
        (BLOCK_QUERY )nullcipher_query,
        "NullCipher"
    },
    #define INDEX_THREEFISH256 1
    {
        (BLOCK_ALLOC )threefish256_alloc,
        (BLOCK_INIT  )threefish256_init,
        (BLOCK_UPDATE)threefish256_forward,
        (BLOCK_UPDATE)threefish256_inverse,
        (BLOCK_FINAL )threefish256_final,
        (BLOCK_FREE  )threefish256_free,
        (BLOCK_COPY  )threefish256_copy,
        (BLOCK_QUERY )threefish256_query,
        "Threefish-256"
    },
    #define INDEX_AES 2
    {
        (BLOCK_ALLOC )aes_alloc,
        (BLOCK_INIT  )aes_init,
        (BLOCK_UPDATE)aes_forward,
        (BLOCK_UPDATE)aes_inverse,
        (BLOCK_FINAL )aes_final,
        (BLOCK_FREE  )aes_free,
        (BLOCK_COPY  )aes_copy,
        (BLOCK_QUERY )aes_query,
        "AES"
    }
};

const struct BLOCK_CIPHER *nullcipher(void)
{
    return primitives + INDEX_NULLCIPHER;
}

const struct BLOCK_CIPHER *threefish256(void)
{
    return primitives + INDEX_THREEFISH256;
}

const struct BLOCK_CIPHER *aes(void)
{
    return primitives + INDEX_AES;
}

//===----------------------------------------------------------------------===//

size_t block_cipher_count(void)
{
    return sizeof(primitives) / sizeof(struct BLOCK_CIPHER);
}

const struct BLOCK_CIPHER *block_cipher_by_name(const char *name)
{
    size_t t;

    for (t = 0; t < block_cipher_count(); t++)
        if (!strcmp(name, primitives[t].name))
            return primitives + t;

    return 0;
}

const struct BLOCK_CIPHER *block_cipher_by_index(size_t index)
{
    return index < block_cipher_count() ? primitives + index : 0;
}

//===----------------------------------------------------------------------===//

void *block_cipher_alloc(const struct BLOCK_CIPHER *primitive)
{
    return primitive->alloc();
}

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

void block_cipher_free(const struct BLOCK_CIPHER *primitive,
                       void *state)
{
    primitive->free(state);
}

void block_cipher_copy(const struct BLOCK_CIPHER *primitive,
                       void *dst,
                       const void *src)
{
    primitive->copy(dst, src);
}

size_t block_cipher_query(const struct BLOCK_CIPHER *primitive,
                          int query, size_t value)
{
    return primitive->query(query, value);
}
