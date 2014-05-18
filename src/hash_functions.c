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
        case HASH_MD5:
            return "MD5";
        case HASH_SHA256:
            return "SHA-256";
        case HASH_SKEIN256:
            return "Skein-256";
        case HASH_UNKNOWN: default:
            return 0;
    }
}

/*===----------------------------------------------------------------------===*/

enum HASH_FUNCTION hash_function_by_name(const char *name)
{
    if (!strcmp(name, "MD5"))
        return HASH_MD5;
    else if (!strcmp(name, "SHA-256"))
        return HASH_SHA256;
    else if (!strcmp(name, "Skein-256"))
        return HASH_SKEIN256;
    else
        return HASH_UNKNOWN;
}

enum HASH_FUNCTION hash_function_by_index(size_t index)
{
    return index;
}

size_t hash_function_count(void)
{
    return HASH_COUNT;
}

/*===----------------------------------------------------------------------===*/

#include "ordo/primitives/hash_functions/md5.h"
#include "ordo/primitives/hash_functions/sha256.h"
#include "ordo/primitives/hash_functions/skein256.h"

int hash_function_init(struct HASH_STATE *state,
                       enum HASH_FUNCTION hash,
                       const void *params)
{
    switch (state->hash = hash)
    {
        case HASH_MD5:
            return md5_init(&state->jmp.md5, params);
        case HASH_SHA256:
            return sha256_init(&state->jmp.sha256, params);
        case HASH_SKEIN256:
            return skein256_init(&state->jmp.skein256, params);
        case HASH_UNKNOWN: default:
            return ORDO_FAIL;
    }
}

void hash_function_update(struct HASH_STATE *state,
                          const void *buffer,
                          size_t len)
{
    switch (state->hash)
    {
        case HASH_MD5:
            return md5_update(&state->jmp.md5, buffer, len);
        case HASH_SHA256:
            return sha256_update(&state->jmp.sha256, buffer, len);
        case HASH_SKEIN256:
            return skein256_update(&state->jmp.skein256, buffer, len);
        case HASH_UNKNOWN: default:
            return;
    }
}

void hash_function_final(struct HASH_STATE *state,
                         void *digest)
{
    switch (state->hash)
    {
        case HASH_MD5:
            return md5_final(&state->jmp.md5, digest);
        case HASH_SHA256:
            return sha256_final(&state->jmp.sha256, digest);
        case HASH_SKEIN256:
            return skein256_final(&state->jmp.skein256, digest);
        case HASH_UNKNOWN: default:
            return;
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
        case HASH_MD5:
            return md5_query(query, value);
        case HASH_SHA256:
            return sha256_query(query, value);
        case HASH_SKEIN256:
            return skein256_query(query, value);
        case HASH_UNKNOWN: default:
            return (size_t)-1;
    }
}
