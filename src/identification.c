/*===-- identification.c ------------------------------*- generic -*- C -*-===*/

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

#include "ordo/common/identification.h"

/*===----------------------------------------------------------------------===*/

static uint32_t fnv32(const char *s)
{
    uint32_t n = UINT32_C(2166136261);

    while (*s) n = (n ^ (uint8_t)*(s++)) * UINT32_C(16777619);
    
    return n;
}

int prim_avail(prim_t prim)
{
    switch (prim)
    {
        case BLOCK_AES:                    return WITH_AES;
        case BLOCK_NULLCIPHER:             return WITH_NULLCIPHER;
        case BLOCK_THREEFISH256:           return WITH_THREEFISH256;
        case HASH_MD5:                     return WITH_MD5;
        case HASH_SHA1:                    return WITH_SHA1;
        case HASH_SHA256:                  return WITH_SHA256;
        case HASH_SKEIN256:                return WITH_SKEIN256;
        case STREAM_RC4:                   return WITH_RC4;
        case BLOCK_MODE_ECB:               return WITH_ECB;
        case BLOCK_MODE_CBC:               return WITH_CBC;
        case BLOCK_MODE_CTR:               return WITH_CTR;
        case BLOCK_MODE_CFB:               return WITH_CFB;
        case BLOCK_MODE_OFB:               return WITH_OFB;
    }
    
    return 0;
}

const char *prim_name(prim_t prim)
{
    if (!prim_avail(prim))
        return 0;

    switch (prim)
    {
        case BLOCK_AES:                    return "AES";
        case BLOCK_NULLCIPHER:             return "NullCipher";
        case BLOCK_THREEFISH256:           return "Threefish-256";
        case HASH_MD5:                     return "MD5";
        case HASH_SHA1:                    return "SHA-1";
        case HASH_SHA256:                  return "SHA-256";
        case HASH_SKEIN256:                return "Skein-256";
        case STREAM_RC4:                   return "RC4";
        case BLOCK_MODE_ECB:               return "ECB";
        case BLOCK_MODE_CBC:               return "CBC";
        case BLOCK_MODE_CTR:               return "CTR";
        case BLOCK_MODE_CFB:               return "CFB";
        case BLOCK_MODE_OFB:               return "OFB";
    }
    
    return 0;
}

enum PRIM_TYPE prim_type(prim_t prim)
{
    if (!prim_avail(prim))
        return 0;

    /* Bits 4..7 of the primitive identifier are the primitive type. */

    switch ((prim >> 4) & 0xF)
    {
        case 0x1: return PRIM_TYPE_HASH;
        case 0x2: return PRIM_TYPE_BLOCK;
        case 0x3: return PRIM_TYPE_STREAM;
        case 0x4: return PRIM_TYPE_BLOCK_MODE;
    }
    
    return PRIM_TYPE_UNKNOWN;
}

prim_t prim_from_name(const char *name)
{
    switch (fnv32(name))
    {
        #if WITH_AES
        case 0xac77e168: return BLOCK_AES;
        #endif
        #if WITH_NULLCIPHER
        case 0xe91180ab: return BLOCK_NULLCIPHER;
        #endif
        #if WITH_THREEFISH256
        case 0x652cf289: return BLOCK_THREEFISH256;
        #endif
        #if WITH_MD5
        case 0x7360d733: return HASH_MD5;
        #endif
        #if WITH_SHA1
        case 0xee353ec3: return HASH_SHA1;
        #endif
        #if WITH_SHA256
        case 0xc64cb93d: return HASH_SHA256;
        #endif
        #if WITH_SKEIN256
        case 0x24488a55: return HASH_SKEIN256;
        #endif
        #if WITH_RC4
        case 0xd7de26c2: return STREAM_RC4;
        #endif
        #if WITH_ECB
        case 0x0b284c61: return BLOCK_MODE_ECB;
        #endif
        #if WITH_CBC
        case 0x4647b2a9: return BLOCK_MODE_CBC;
        #endif
        #if WITH_CTR
        case 0x352e0000: return BLOCK_MODE_CTR;
        #endif
        #if WITH_CFB
        case 0x5d50d13a: return BLOCK_MODE_CFB;
        #endif
        #if WITH_OFB
        case 0x2a14ff9e: return BLOCK_MODE_OFB;
        #endif
    }
    
    return 0;
}

const prim_t *prims_by_type(enum PRIM_TYPE type)
{
    static const prim_t hash[] =
    {
        #if WITH_MD5
        HASH_MD5,
        #endif
        #if WITH_SHA1
        HASH_SHA1,
        #endif
        #if WITH_SHA256
        HASH_SHA256,
        #endif
        #if WITH_SKEIN256
        HASH_SKEIN256,
        #endif
        0
    };

    static const prim_t stream[] =
    {
        #if WITH_RC4
        STREAM_RC4,
        #endif
        0
    };

    static const prim_t block[] =
    {
        #if WITH_AES
        BLOCK_AES,
        #endif
        #if WITH_THREEFISH256
        BLOCK_THREEFISH256,
        #endif
        #if WITH_NULLCIPHER
        BLOCK_NULLCIPHER,
        #endif
        0
    };

    static const prim_t block_mode[] =
    {
        #if WITH_ECB
        BLOCK_MODE_ECB,
        #endif
        #if WITH_CBC
        BLOCK_MODE_CBC,
        #endif
        #if WITH_CTR
        BLOCK_MODE_CTR,
        #endif
        #if WITH_CFB
        BLOCK_MODE_CFB,
        #endif
        #if WITH_OFB
        BLOCK_MODE_OFB,
        #endif
        0
    };

    switch (type)
    {
        case PRIM_TYPE_UNKNOWN:          return 0;
        case PRIM_TYPE_HASH:             return hash;
        case PRIM_TYPE_STREAM:           return stream;
        case PRIM_TYPE_BLOCK:            return block;
        case PRIM_TYPE_BLOCK_MODE:       return block_mode;
    }

    return 0;
}

prim_t prim_default(enum PRIM_TYPE type)
{
    switch (type)
    {
        case PRIM_TYPE_UNKNOWN:
            return 0;
        case PRIM_TYPE_HASH:
            #if WITH_SHA256
            return HASH_SHA256;
            #elif WITH_SHA1
            return HASH_SHA1;
            #elif WITH_SKEIN256
            return HASH_SKEIN256;
            #elif WITH_MD5
            return HASH_MD5;
            #else
            return 0;
            #endif
        case PRIM_TYPE_STREAM:
            #if WITH_RC4
            return STREAM_RC4;
            #else
            return 0;
            #endif
        case PRIM_TYPE_BLOCK:
            #if WITH_AES
            return BLOCK_AES;
            #elif WITH_THREEFISH256
            return BLOCK_THREEFISH256;
            #elif WITH_NULLCIPHER
            return BLOCK_NULLCIPHER; /* ... */
            #else
            return 0;
            #endif
        case PRIM_TYPE_BLOCK_MODE:
            #if WITH_CTR
            return BLOCK_MODE_CTR;
            #elif WITH_CFB
            return BLOCK_MODE_CFB;
            #elif WITH_OFB
            return BLOCK_MODE_OFB;
            #elif WITH_CBC
            return BLOCK_MODE_CBC;
            #elif WITH_ECB
            return BLOCK_MODE_ECB;
            #else
            return 0;
            #endif
    }

    return 0;
}
