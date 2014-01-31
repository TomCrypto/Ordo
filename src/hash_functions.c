//===-- hash_functions.c ------------------------------*- generic -*- C -*-===//

#include "ordo/primitives/hash_functions.h"

/// @cond
#include "ordo/internal/implementation.h"
/// @endcond

//===----------------------------------------------------------------------===//

typedef void  *(*HASH_ALLOC)
    (void);
typedef  int   (*HASH_INIT)
    (void *, const void *);
typedef void   (*HASH_UPDATE)
    (void *, const void *, size_t);
typedef void   (*HASH_FINAL)
    (void *, void *);
typedef void   (*HASH_FREE)
    (void *);
typedef void   (*HASH_COPY)
    (void *, const void *);
typedef size_t (*HASH_QUERY)
    (int, size_t);

struct HASH_FUNCTION
{
    HASH_ALLOC  alloc;
    HASH_INIT   init;
    HASH_UPDATE update;
    HASH_FINAL  final;
    HASH_FREE   free;
    HASH_COPY   copy;
    HASH_QUERY  query;
    const char *name;
};

//===----------------------------------------------------------------------===//

const char *hash_function_name(const struct HASH_FUNCTION *primitive)
{
    return primitive->name;
}

#include "ordo/primitives/hash_functions/md5.h"
#include "ordo/primitives/hash_functions/sha256.h"
#include "ordo/primitives/hash_functions/skein256.h"

static struct HASH_FUNCTION primitives[] =
{
    #define INDEX_MD5 0
    {
        (HASH_ALLOC )md5_alloc,
        (HASH_INIT  )md5_init,
        (HASH_UPDATE)md5_update,
        (HASH_FINAL )md5_final,
        (HASH_FREE  )md5_free,
        (HASH_COPY  )md5_copy,
        (HASH_QUERY )md5_query,
        "MD5"
    },
    #define INDEX_SHA256 1
    {
        (HASH_ALLOC )sha256_alloc,
        (HASH_INIT  )sha256_init,
        (HASH_UPDATE)sha256_update,
        (HASH_FINAL )sha256_final,
        (HASH_FREE  )sha256_free,
        (HASH_COPY  )sha256_copy,
        (HASH_QUERY )sha256_query,
        "SHA-256"
    },
    #define INDEX_SKEIN256 2
    {
        (HASH_ALLOC )skein256_alloc,
        (HASH_INIT  )skein256_init,
        (HASH_UPDATE)skein256_update,
        (HASH_FINAL )skein256_final,
        (HASH_FREE  )skein256_free,
        (HASH_COPY  )skein256_copy,
        (HASH_QUERY )skein256_query,
        "Skein-256"
    }
};

const struct HASH_FUNCTION *sha256(void)
{
    return primitives + INDEX_SHA256;
}

const struct HASH_FUNCTION *md5(void)
{
    return primitives + INDEX_MD5;
}

const struct HASH_FUNCTION *skein256(void)
{
    return primitives + INDEX_SKEIN256;
}

//===----------------------------------------------------------------------===//

size_t hash_function_count(void)
{
    return sizeof(primitives) / sizeof(struct HASH_FUNCTION);
}

const struct HASH_FUNCTION *hash_function_by_name(const char *name)
{
    size_t t;

    for (t = 0; t < hash_function_count(); t++)
        if (!strcmp(name, primitives[t].name))
            return primitives + t;

    return 0;
}

const struct HASH_FUNCTION *hash_function_by_index(size_t index)
{
    return index < hash_function_count() ? primitives + index : 0;
}

//===----------------------------------------------------------------------===//

void *hash_function_alloc(const struct HASH_FUNCTION *primitive)
{
    return primitive->alloc();
}

int hash_function_init(const struct HASH_FUNCTION *primitive,
                       void *state,
                       const void *params)
{
    return primitive->init(state, params);
}

void hash_function_update(const struct HASH_FUNCTION *primitive,
                          void *state,
                          const void *buffer,
                          size_t len)
{
    primitive->update(state, buffer, len);
}

void hash_function_final(const struct HASH_FUNCTION *primitive,
                         void *state,
                         void *digest)
{
    primitive->final(state, digest);
}

void hash_function_free(const struct HASH_FUNCTION *primitive,
                        void *state)
{
    primitive->free(state);
}

void hash_function_copy(const struct HASH_FUNCTION *primitive,
                        void *dst,
                        const void *src)
{
    primitive->copy(dst, src);
}

size_t hash_function_query(const struct HASH_FUNCTION *primitive,
                           int query, size_t value)
{
    return primitive->query(query, value);
}