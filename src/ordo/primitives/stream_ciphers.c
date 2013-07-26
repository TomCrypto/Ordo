#include "ordo/primitives/stream_ciphers.h"

#include <string.h>

/******************************************************************************/

typedef void* (*STREAM_ALLOC)   (void                                   );
typedef  int  (*STREAM_INIT)    (void*, const void*, size_t, const void*);
typedef void  (*STREAM_UPDATE)  (void*,       void*, size_t             );
typedef void  (*STREAM_FREE)    (void*                                  );
typedef void  (*STREAM_COPY)    (void*, const void*                     );
typedef size_t (*STREAM_QUERY)  (int, size_t                            );

struct STREAM_CIPHER
{
    STREAM_ALLOC alloc;
    STREAM_INIT init;
    STREAM_UPDATE update;
    STREAM_FREE free;
    STREAM_COPY copy;
    STREAM_QUERY query;
    const char* name;
};

/******************************************************************************/

const char *stream_cipher_name(const struct STREAM_CIPHER *primitive)
{
    return primitive->name;
}

/******************************************************************************/

#include "ordo/primitives/stream_ciphers/rc4.h"

static struct STREAM_CIPHER primitives[] =
{
    #define RC4_ID 0
    {
        (STREAM_ALLOC)rc4_alloc,
        (STREAM_INIT)rc4_init,
        (STREAM_UPDATE)rc4_update,
        (STREAM_FREE)rc4_free,
        (STREAM_COPY)rc4_copy,
        (STREAM_QUERY)rc4_query,
        "RC4"
    }
};

const struct STREAM_CIPHER *rc4(void)
{
    return &primitives[RC4_ID];
}

/******************************************************************************/

size_t stream_cipher_count(void)
{
    return sizeof(primitives) / sizeof(struct STREAM_CIPHER);
}

const struct STREAM_CIPHER* stream_cipher_by_name(const char *name)
{
    size_t t;

    for (t = 0; t < stream_cipher_count(); t++)
    {
        size_t len = strlen(primitives[t].name);
        if (!strncmp(name, primitives[t].name, len))
            return &primitives[t];
    }

    return 0;
}

const struct STREAM_CIPHER *stream_cipher_by_id(size_t id)
{
    return (id < stream_cipher_count()) ? &primitives[id] : 0;
}

/******************************************************************************/

void *stream_cipher_alloc(const struct STREAM_CIPHER *primitive)
{
    return primitive->alloc();
}

int stream_cipher_init(const struct STREAM_CIPHER *primitive,
                       void* state,
                       const void *key,
                       size_t key_len,
                       const void *params)
{
    return primitive->init(state, key, key_len, params);
}

void stream_cipher_update(const struct STREAM_CIPHER *primitive,
                          void* state,
                          void *buffer,
                          size_t len)
{
    primitive->update(state, buffer, len);
}

void stream_cipher_free(const struct STREAM_CIPHER *primitive,
                        void *state)
{
    primitive->free(state);
}

void stream_cipher_copy(const struct STREAM_CIPHER *primitive,
                        void *dst,
                        const void *src)
{
    primitive->copy(dst, src);
}

size_t stream_cipher_query(const struct STREAM_CIPHER *primitive,
                           int query, size_t value)
{
    return primitive->query(query, value);
}
