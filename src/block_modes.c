//===-- block_modes.c ---------------------------------*- generic -*- C -*-===//

#include "ordo/primitives/block_modes.h"

/// @cond
#include "ordo/internal/implementation.h"
/// @endcond

//===----------------------------------------------------------------------===//

typedef void  *(*BLOCK_MODE_ALLOC)
    (const struct BLOCK_CIPHER *, const void *);

typedef int    (*BLOCK_MODE_INIT)
    (void *, const struct BLOCK_CIPHER *, const void *,
     const void *, size_t, int, const void *);

typedef void   (*BLOCK_MODE_UPDATE)
    (void *, const struct BLOCK_CIPHER *, const void *,
     const void *, size_t, void *, size_t *);

typedef int    (*BLOCK_MODE_FINAL)
    (void *, const struct BLOCK_CIPHER *, const void *, void *, size_t *);

typedef void   (*BLOCK_MODE_FREE)
    (void *, const struct BLOCK_CIPHER *, const void *);

typedef size_t (*BLOCK_MODE_QUERY)
    (const struct BLOCK_CIPHER *, int, size_t);

typedef void   (*BLOCK_MODE_COPY)
    (void *, const void *, const struct BLOCK_CIPHER *);

struct BLOCK_MODE
{
    BLOCK_MODE_ALLOC  alloc;
    BLOCK_MODE_INIT   init;
    BLOCK_MODE_UPDATE update;
    BLOCK_MODE_FINAL  final;
    BLOCK_MODE_FREE   free;
    BLOCK_MODE_COPY   copy;
    BLOCK_MODE_QUERY  query;
    const char       *name;
};

//===----------------------------------------------------------------------===//

const char *block_mode_name(const struct BLOCK_MODE *mode)
{
    return mode->name;
}

#include "ordo/primitives/block_modes/ecb.h"
#include "ordo/primitives/block_modes/cbc.h"
#include "ordo/primitives/block_modes/ctr.h"
#include "ordo/primitives/block_modes/cfb.h"
#include "ordo/primitives/block_modes/ofb.h"

static struct BLOCK_MODE primitives[] =
{
    #define INDEX_ECB 0
    {
        (BLOCK_MODE_ALLOC )ecb_alloc,
        (BLOCK_MODE_INIT  )ecb_init,
        (BLOCK_MODE_UPDATE)ecb_update,
        (BLOCK_MODE_FINAL )ecb_final,
        (BLOCK_MODE_FREE  )ecb_free,
        (BLOCK_MODE_COPY  )ecb_copy,
        (BLOCK_MODE_QUERY )ecb_query,
        "ECB"
    },
    #define INDEX_CBC 1
    {
        (BLOCK_MODE_ALLOC )cbc_alloc,
        (BLOCK_MODE_INIT  )cbc_init,
        (BLOCK_MODE_UPDATE)cbc_update,
        (BLOCK_MODE_FINAL )cbc_final,
        (BLOCK_MODE_FREE  )cbc_free,
        (BLOCK_MODE_COPY  )cbc_copy,
        (BLOCK_MODE_QUERY )cbc_query,
        "CBC"
    },
    #define INDEX_CTR 2
    {
        (BLOCK_MODE_ALLOC )ctr_alloc,
        (BLOCK_MODE_INIT  )ctr_init,
        (BLOCK_MODE_UPDATE)ctr_update,
        (BLOCK_MODE_FINAL )ctr_final,
        (BLOCK_MODE_FREE  )ctr_free,
        (BLOCK_MODE_COPY  )ctr_copy,
        (BLOCK_MODE_QUERY )ctr_query,
        "CTR"
    },
    #define INDEX_CFB 3
    {
        (BLOCK_MODE_ALLOC )cfb_alloc,
        (BLOCK_MODE_INIT  )cfb_init,
        (BLOCK_MODE_UPDATE)cfb_update,
        (BLOCK_MODE_FINAL )cfb_final,
        (BLOCK_MODE_FREE  )cfb_free,
        (BLOCK_MODE_COPY  )cfb_copy,
        (BLOCK_MODE_QUERY )cfb_query,
        "CFB"
    },
    #define INDEX_OFB 4
    {
        (BLOCK_MODE_ALLOC )ofb_alloc,
        (BLOCK_MODE_INIT  )ofb_init,
        (BLOCK_MODE_UPDATE)ofb_update,
        (BLOCK_MODE_FINAL )ofb_final,
        (BLOCK_MODE_FREE  )ofb_free,
        (BLOCK_MODE_COPY  )ofb_copy,
        (BLOCK_MODE_QUERY )ofb_query,
        "OFB"
    }
};

const struct BLOCK_MODE *ecb(void)
{
    return primitives + INDEX_ECB;
}

const struct BLOCK_MODE *cbc(void)
{
    return primitives + INDEX_CBC;
}

const struct BLOCK_MODE *ctr(void)
{
    return primitives + INDEX_CTR;
}

const struct BLOCK_MODE *cfb(void)
{
    return primitives + INDEX_CFB;
}

const struct BLOCK_MODE *ofb(void)
{
    return primitives + INDEX_OFB;
}

//===----------------------------------------------------------------------===//

size_t block_mode_count(void)
{
    return sizeof(primitives) / sizeof(struct BLOCK_MODE);
}

const struct BLOCK_MODE *block_mode_by_name(const char *name)
{
    size_t t;

    for (t = 0; t < block_mode_count(); t++)
        if (!strcmp(name, primitives[t].name))
            return primitives + t;

    return 0;
}

const struct BLOCK_MODE *block_mode_by_index(size_t index)
{
    return index < block_mode_count() ? primitives + index : 0;
}

//===----------------------------------------------------------------------===//

void *block_mode_alloc(const struct BLOCK_MODE *mode,
                       const struct BLOCK_CIPHER *cipher,
                       const void *cipher_state)
{
    return mode->alloc(cipher, cipher_state);
}

int block_mode_init(const struct BLOCK_MODE *mode,
                    void *state,
                    const struct BLOCK_CIPHER *cipher,
                    const void *cipher_state,
                    const void *iv, size_t iv_len,
                    int direction,
                    const void *params)
{
    return mode->init(state,
                      cipher, cipher_state,
                      iv, iv_len,
                      direction,
                      params);
}

void block_mode_update(const struct BLOCK_MODE *mode,
                       void *state,
                       const struct BLOCK_CIPHER *cipher,
                       const void *cipher_state,
                       const void *in, size_t in_len,
                       void *out, size_t *out_len)
{
    mode->update(state, cipher, cipher_state, in, in_len, out, out_len);
}

int block_mode_final(const struct BLOCK_MODE *mode,
                     void *state,
                     const struct BLOCK_CIPHER *cipher,
                     const void *cipher_state,
                     void *out, size_t *out_len)
{
    return mode->final(state, cipher, cipher_state, out, out_len);
}

void block_mode_free(const struct BLOCK_MODE *mode,
                     void *state,
                     const struct BLOCK_CIPHER *cipher,
                     const void *cipher_state)
{
    mode->free(state, cipher, cipher_state);
}

size_t block_mode_query(const struct BLOCK_MODE *mode,
                        const struct BLOCK_CIPHER *cipher,
                        int query, size_t value)
{
    return mode->query(cipher, query, value);
}

void block_mode_copy(const struct BLOCK_MODE *mode,
                     const struct BLOCK_CIPHER *cipher,
                     void *dst,
                     const void *src)
{
    mode->copy(dst, src, cipher);
}
