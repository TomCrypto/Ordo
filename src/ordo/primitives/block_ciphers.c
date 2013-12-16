#include "ordo/primitives/block_ciphers.h"

#include "ordo/common/identification.h"

#include <string.h>

/******************************************************************************/

typedef void  *(ORDO_CALLCONV *BLOCK_ALLOC)
    (void);
typedef  int   (ORDO_CALLCONV *BLOCK_INIT)
    (void *, const void *, size_t, const void *);
typedef void   (ORDO_CALLCONV *BLOCK_UPDATE)
    (void *, void *);
typedef void   (ORDO_CALLCONV *BLOCK_FREE)
    (void *);
typedef void   (ORDO_CALLCONV *BLOCK_COPY)
    (void *, const void *);
typedef size_t (ORDO_CALLCONV *BLOCK_QUERY)
    (int, size_t);

struct BLOCK_CIPHER
{
    BLOCK_ALLOC alloc;
    BLOCK_INIT init;
    BLOCK_UPDATE forward;
    BLOCK_UPDATE inverse;
    BLOCK_FREE free;
    BLOCK_COPY copy;
    BLOCK_QUERY query;
    const char *name;
};

/******************************************************************************/

const char * ORDO_CALLCONV
block_cipher_name(const struct BLOCK_CIPHER *primitive)
{
    return primitive->name;
}

/******************************************************************************/

#include "ordo/primitives/block_ciphers/nullcipher.h"
#include "ordo/primitives/block_ciphers/threefish256.h"
#include "ordo/primitives/block_ciphers/aes.h"

static struct BLOCK_CIPHER primitives[] =
{
    #define NULLCIPHER_ID 0
    {
        (BLOCK_ALLOC)nullcipher_alloc,
        (BLOCK_INIT)nullcipher_init,
        (BLOCK_UPDATE)nullcipher_forward,
        (BLOCK_UPDATE)nullcipher_inverse,
        (BLOCK_FREE)nullcipher_free,
        (BLOCK_COPY)nullcipher_copy,
        (BLOCK_QUERY)nullcipher_query,
        "NullCipher"
    },
    #define THREEFISH256_ID 1
    {
        (BLOCK_ALLOC)threefish256_alloc,
        (BLOCK_INIT)threefish256_init,
        (BLOCK_UPDATE)threefish256_forward,
        (BLOCK_UPDATE)threefish256_inverse,
        (BLOCK_FREE)threefish256_free,
        (BLOCK_COPY)threefish256_copy,
        (BLOCK_QUERY)threefish256_query,
        "Threefish-256"
    },
    #define AES_ID 2
    {
        (BLOCK_ALLOC)aes_alloc,
        (BLOCK_INIT)aes_init,
        (BLOCK_UPDATE)aes_forward,
        (BLOCK_UPDATE)aes_inverse,
        (BLOCK_FREE)aes_free,
        (BLOCK_COPY)aes_copy,
        (BLOCK_QUERY)aes_query,
        "AES"
    }
};

const struct BLOCK_CIPHER * ORDO_CALLCONV
nullcipher(void)
{
    return &primitives[NULLCIPHER_ID];
}

const struct BLOCK_CIPHER * ORDO_CALLCONV
threefish256(void)
{
    return &primitives[THREEFISH256_ID];
}

const struct BLOCK_CIPHER * ORDO_CALLCONV
aes(void)
{
    return &primitives[AES_ID];
}

/******************************************************************************/

size_t ORDO_CALLCONV
block_cipher_count(void)
{
    return sizeof(primitives) / sizeof(struct BLOCK_CIPHER);
}

const struct BLOCK_CIPHER * ORDO_CALLCONV
block_cipher_by_name(const char *name)
{
    size_t t;

    for (t = 0; t < block_cipher_count(); t++)
    {
        size_t len = strlen(primitives[t].name);
        if (!strncmp(name, primitives[t].name, len))
            return &primitives[t];
    }

    return 0;
}

const struct BLOCK_CIPHER * ORDO_CALLCONV
block_cipher_by_index(size_t index)
{
    return (index < block_cipher_count()) ? &primitives[index] : 0;
}

const struct BLOCK_CIPHER * ORDO_CALLCONV
block_cipher_by_id(size_t id)
{
    switch (id)
    {
        case BLOCK_NULLCIPHER       : return &primitives[NULLCIPHER_ID];
        case BLOCK_AES              : return &primitives[AES_ID];
        case BLOCK_THREEFISH256     : return &primitives[THREEFISH256_ID];
        default                     : return 0;
    }
}

/******************************************************************************/

void * ORDO_CALLCONV
block_cipher_alloc(const struct BLOCK_CIPHER *primitive)
{
    return primitive->alloc();
}

int ORDO_CALLCONV
block_cipher_init(const struct BLOCK_CIPHER *primitive,
                  void *state,
                  const void *key,
                  size_t key_len,
                  const void *params)
{
    return primitive->init(state, key, key_len, params);
}

void ORDO_CALLCONV
block_cipher_forward(const struct BLOCK_CIPHER *primitive,
                     void *state,
                     void *block)
{
    primitive->forward(state, block);
}

void ORDO_CALLCONV
block_cipher_inverse(const struct BLOCK_CIPHER *primitive,
                     void *state,
                     void *block)
{
    primitive->inverse(state, block);
}

void ORDO_CALLCONV
block_cipher_free(const struct BLOCK_CIPHER *primitive,
                  void *state)
{
    primitive->free(state);
}

void ORDO_CALLCONV
block_cipher_copy(const struct BLOCK_CIPHER *primitive,
                  void *dst,
                  const void *src)
{
    primitive->copy(dst, src);
}

size_t ORDO_CALLCONV
block_cipher_query(const struct BLOCK_CIPHER *primitive,
                   int query, size_t value)
{
    return primitive->query(query, value);
}
