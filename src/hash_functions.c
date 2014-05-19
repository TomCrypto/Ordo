/*===-- hash_functions.c ------------------------------*- generic -*- C -*-===*/

#include "ordo/primitives/hash_functions.h"

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

/*===----------------------------------------------------------------------===*/

const char *hash_function_name(enum HASH_FUNCTION primitive)
{
    switch (primitive)
    {
#ifdef USING_MD5
        case HASH_MD5:
            return "MD5";
#endif
#ifdef USING_SHA256
        case HASH_SHA256:
            return "SHA-256";
#endif
#ifdef USING_SKEIN256
        case HASH_SKEIN256:
            return "Skein-256";
#endif
        default:
            return 0;
    }
}

/*===----------------------------------------------------------------------===*/

enum HASH_FUNCTION hash_function_by_name(const char *name)
{
#ifdef USING_MD5
    if (!strcmp(name, "MD5"))
        return HASH_MD5;
#endif

#ifdef USING_SHA256
    if (!strcmp(name, "SHA-256"))
        return HASH_SHA256;
#endif

#ifdef USING_SKEIN256
    if (!strcmp(name, "Skein-256"))
        return HASH_SKEIN256;
#endif

    return 0;
}

enum HASH_FUNCTION hash_function_by_index(size_t index)
{
    switch (index)
    {
#ifdef USING_MD5
        case __COUNTER__: return HASH_MD5;
#endif
#ifdef USING_SHA256
        case __COUNTER__: return HASH_SHA256;
#endif
#ifdef USING_SKEIN256
        case __COUNTER__: return HASH_SKEIN256;
#endif

        default:          return 0;
    }
}

size_t hash_function_count(void)
{
    return __COUNTER__;
}

/*===----------------------------------------------------------------------===*/

#ifdef USING_MD5
    #include "ordo/primitives/hash_functions/md5.h"
#endif
#ifdef USING_SHA256
    #include "ordo/primitives/hash_functions/sha256.h"
#endif
#ifdef USING_SKEIN256
    #include "ordo/primitives/hash_functions/skein256.h"
#endif

int hash_function_init(struct HASH_STATE *state,
                       enum HASH_FUNCTION hash,
                       const void *params)
{
    switch (state->hash = hash)
    {
#ifdef USING_MD5
        case HASH_MD5:
            return md5_init(&state->jmp.md5, params);
#endif
#ifdef USING_SHA256
        case HASH_SHA256:
            return sha256_init(&state->jmp.sha256, params);
#endif
#ifdef USING_SKEIN256
        case HASH_SKEIN256:
            return skein256_init(&state->jmp.skein256, params);
#endif
    }
    
    return ORDO_FAIL;
}

void hash_function_update(struct HASH_STATE *state,
                          const void *buffer,
                          size_t len)
{
    switch (state->hash)
    {
#ifdef USING_MD5
        case HASH_MD5:
            return md5_update(&state->jmp.md5, buffer, len);
#endif
#ifdef USING_SHA256
        case HASH_SHA256:
            return sha256_update(&state->jmp.sha256, buffer, len);
#endif
#ifdef USING_SKEIN256
        case HASH_SKEIN256:
            return skein256_update(&state->jmp.skein256, buffer, len);
#endif
    }
}

void hash_function_final(struct HASH_STATE *state,
                         void *digest)
{
    switch (state->hash)
    {
#ifdef USING_MD5
        case HASH_MD5:
            return md5_final(&state->jmp.md5, digest);
#endif
#ifdef USING_SHA256
        case HASH_SHA256:
            return sha256_final(&state->jmp.sha256, digest);
#endif
#ifdef USING_SKEIN256
        case HASH_SKEIN256:
            return skein256_final(&state->jmp.skein256, digest);
#endif
    }
}

void hash_function_copy(struct HASH_STATE *dst,
                        const struct HASH_STATE *src)
{
    *dst = *src;
}

size_t hash_function_query(enum HASH_FUNCTION hash,
                           int query, size_t value)
{
    switch (hash)
    {
#ifdef USING_MD5
        case HASH_MD5:
            return md5_query(query, value);
#endif
#ifdef USING_SHA256
        case HASH_SHA256:
            return sha256_query(query, value);
#endif
#ifdef USING_SKEIN256
        case HASH_SKEIN256:
            return skein256_query(query, value);
#endif
    }
    
    return (size_t)-1;
}
