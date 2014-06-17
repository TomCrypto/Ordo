/*===-- hash_functions.c ------------------------------*- generic -*- C -*-===*/

#include "ordo/primitives/hash_functions.h"

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

/*===----------------------------------------------------------------------===*/

#if WITH_MD5
#include "ordo/primitives/hash_functions/md5.h"
#endif
#if WITH_SHA256
#include "ordo/primitives/hash_functions/sha256.h"
#endif
#if WITH_SKEIN256
#include "ordo/primitives/hash_functions/skein256.h"
#endif

int hash_function_init(struct HASH_STATE *state,
                       prim_t primitive, const void *params)
{
    switch (state->primitive = primitive)
    {
        #if WITH_MD5
        case HASH_MD5:
            return md5_init(&state->jmp.md5, params);
        #endif
        #if WITH_SHA256
        case HASH_SHA256:
            return sha256_init(&state->jmp.sha256, params);
        #endif
        #if WITH_SKEIN256
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
    switch (state->primitive)
    {
        #if WITH_MD5
        case HASH_MD5:
            md5_update(&state->jmp.md5, buffer, len);
            break;
        #endif
        #if WITH_SHA256
        case HASH_SHA256:
            sha256_update(&state->jmp.sha256, buffer, len);
            break;
        #endif
        #if WITH_SKEIN256
        case HASH_SKEIN256:
            skein256_update(&state->jmp.skein256, buffer, len);
            break;
        #endif
    }
}

void hash_function_final(struct HASH_STATE *state,
                         void *digest)
{
    switch (state->primitive)
    {
        #if WITH_MD5
        case HASH_MD5:
            md5_final(&state->jmp.md5, digest);
            break;
        #endif
        #if WITH_SHA256
        case HASH_SHA256:
            sha256_final(&state->jmp.sha256, digest);
            break;
        #endif
        #if WITH_SKEIN256
        case HASH_SKEIN256:
            skein256_final(&state->jmp.skein256, digest);
            break;
        #endif
    }
}

size_t hash_function_query(prim_t primitive,
                           int query, size_t value)
{
    switch (primitive)
    {
        #if WITH_MD5
        case HASH_MD5:
            return md5_query(query, value);
        #endif
        #if WITH_SHA256
        case HASH_SHA256:
            return sha256_query(query, value);
        #endif
        #if WITH_SKEIN256
        case HASH_SKEIN256:
            return skein256_query(query, value);
        #endif
    }
    
    return (size_t)-1;
}
