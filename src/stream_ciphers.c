/*===-- stream_ciphers.c ------------------------------*- generic -*- C -*-===*/

#include "ordo/primitives/stream_ciphers.h"

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

/*===----------------------------------------------------------------------===*/

typedef void  *(*STREAM_ALLOC)
    (void);
typedef  int   (*STREAM_INIT)
    (void *, const void *, size_t, const void *);
typedef void   (*STREAM_UPDATE)
    (void *, void *, size_t);
typedef void   (*STREAM_FINAL)
    (void *);
typedef void   (*STREAM_FREE)
    (void *);
typedef void   (*STREAM_COPY)
    (void *, const void *);
typedef size_t (*STREAM_QUERY)
    (int, size_t);

struct STREAM_CIPHER
{
    STREAM_ALLOC  alloc;
    STREAM_INIT   init;
    STREAM_UPDATE update;
    STREAM_FINAL  final;
    STREAM_FREE   free;
    STREAM_COPY   copy;
    STREAM_QUERY  query;
    const char   *name;
};

/*===----------------------------------------------------------------------===*/

const char *stream_cipher_name(const struct STREAM_CIPHER *primitive)
{
    return primitive->name;
}

#include "ordo/primitives/stream_ciphers/rc4.h"

const struct STREAM_CIPHER *ordo_rc4(void)
{
    static const struct STREAM_CIPHER primitive =
    {
        (STREAM_ALLOC )rc4_alloc,
        (STREAM_INIT  )rc4_init,
        (STREAM_UPDATE)rc4_update,
        (STREAM_FINAL )rc4_final,
        (STREAM_FREE  )rc4_free,
        (STREAM_COPY  )rc4_copy,
        (STREAM_QUERY )rc4_query,
        "RC4"
    };

    return &primitive;
}

/*===----------------------------------------------------------------------===*/

const struct STREAM_CIPHER *stream_cipher_by_name(const char *name)
{
    size_t t;

    for (t = 0; t < stream_cipher_count(); t++)
    {
        const struct STREAM_CIPHER *primitive;
        primitive = stream_cipher_by_index(t);

        if (!strcmp(name, primitive->name))
            return primitive;
    }

    return 0;
}

const struct STREAM_CIPHER *stream_cipher_by_index(size_t index)
{
    switch (index)
    {
        case __COUNTER__: return ordo_rc4();

        default: return 0;
    }
}

size_t stream_cipher_count(void)
{
    return __COUNTER__;
}

/*===----------------------------------------------------------------------===*/

void *stream_cipher_alloc(const struct STREAM_CIPHER *primitive)
{
    return primitive->alloc();
}

int stream_cipher_init(const struct STREAM_CIPHER *primitive,
                       void *state,
                       const void *key,
                       size_t key_len,
                       const void *params)
{
    return primitive->init(state, key, key_len, params);
}

void stream_cipher_update(const struct STREAM_CIPHER *primitive,
                          void *state,
                          void *buffer,
                          size_t len)
{
    primitive->update(state, buffer, len);
}

void stream_cipher_final(const struct STREAM_CIPHER *primitive,
                         void *state)
{
    primitive->final(state);
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