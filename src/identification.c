/*===-- identification.c ------------------------------*- generic -*- C -*-===*/

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

/*===----------------------------------------------------------------------===*/

static uint32_t fnv32(const char *s)
{
    uint32_t n = 2166136261;

    while (*s) n = (n ^ *(s++)) * 16777619;
    
    return n;
}

const char *prim_name(prim_t prim)
{
    switch (prim)
    {
        case BLOCK_AES:                    return "AES";
        case BLOCK_NULLCIPHER:             return "NullCipher";
        case BLOCK_THREEFISH256:           return "Threefish-256";
        case HASH_MD5:                     return "MD5";
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

prim_t prim_from_name(const char *name)
{
    switch (fnv32(name))
    {
        case 0xac77e168: return BLOCK_AES;
        case 0xe91180ab: return BLOCK_NULLCIPHER;
        case 0x652cf289: return BLOCK_THREEFISH256;
        case 0x7360d733: return HASH_MD5;
        case 0xc64cb93d: return HASH_SHA256;
        case 0x24488a55: return HASH_SKEIN256;
        case 0xd7de26c2: return STREAM_RC4;
        case 0x0b284c61: return BLOCK_MODE_ECB;
        case 0x4647b2a9: return BLOCK_MODE_CBC;
        case 0x352e0000: return BLOCK_MODE_CTR;
        case 0x5d50d13a: return BLOCK_MODE_CFB;
        case 0x2a14ff9e: return BLOCK_MODE_CTR;
    }
    
    return 0;
}

int prim_available(prim_t prim)
{
    switch (prim)
    {
        case BLOCK_AES:                    return USING_AES;
        case BLOCK_NULLCIPHER:             return USING_NULLCIPHER;
        case BLOCK_THREEFISH256:           return USING_THREEFISH256;
        case HASH_MD5:                     return USING_MD5;
        case HASH_SHA256:                  return USING_SHA256;
        case HASH_SKEIN256:                return USING_SKEIN256;
        case STREAM_RC4:                   return USING_RC4;
        case BLOCK_MODE_ECB:               return USING_ECB;
        case BLOCK_MODE_CBC:               return USING_CBC;
        case BLOCK_MODE_CTR:               return USING_CTR;
        case BLOCK_MODE_CFB:               return USING_CFB;
        case BLOCK_MODE_OFB:               return USING_OFB;
    }
    
    return 0;
}

const prim_t *prim_from_type(int type)
{
    static const prim_t hash[] =
    {
        #if USING_MD5
        HASH_MD5,
        #endif
        #if USING_SHA256
        HASH_SHA256,
        #endif
        #if USING_SKEIN256
        HASH_SKEIN256,
        #endif
        0
    };

    static const prim_t stream[] =
    {
        #if USING_RC4
        STREAM_RC4,
        #endif
        0
    };

    static const prim_t block[] =
    {
        #if USING_AES
        BLOCK_AES,
        #endif
        #if USING_THREEFISH256
        BLOCK_THREEFISH256,
        #endif
        #if USING_NULLCIPHER
        BLOCK_NULLCIPHER,
        #endif
        0
    };

    static const prim_t block_modes[] =
    {
        #if USING_ECB
        BLOCK_MODE_ECB,
        #endif
        #if USING_CBC
        BLOCK_MODE_CBC,
        #endif
        #if USING_CTR
        BLOCK_MODE_CTR,
        #endif
        #if USING_CFB
        BLOCK_MODE_CFB,
        #endif
        #if USING_OFB
        BLOCK_MODE_OFB,
        #endif
        0
    };

    switch (type)
    {
        case PRIM_TYPE_HASH:             return hash;
        case PRIM_TYPE_STREAM:           return stream;
        case PRIM_TYPE_BLOCK:            return block;
        case PRIM_TYPE_BLOCK_MODE:       return block_modes;
    }
    
    return 0;
}

int prim_type(prim_t prim)
{
    if (!prim_available(prim))
        return 0;

    switch (prim)
    {
        case BLOCK_AES:                    return PRIM_TYPE_BLOCK;
        case BLOCK_NULLCIPHER:             return PRIM_TYPE_BLOCK;
        case BLOCK_THREEFISH256:           return PRIM_TYPE_BLOCK;
        case HASH_MD5:                     return PRIM_TYPE_HASH;
        case HASH_SHA256:                  return PRIM_TYPE_HASH;
        case HASH_SKEIN256:                return PRIM_TYPE_HASH;
        case STREAM_RC4:                   return PRIM_TYPE_STREAM;
        case BLOCK_MODE_ECB:               return PRIM_TYPE_BLOCK_MODE;
        case BLOCK_MODE_CBC:               return PRIM_TYPE_BLOCK_MODE;
        case BLOCK_MODE_CTR:               return PRIM_TYPE_BLOCK_MODE;
        case BLOCK_MODE_CFB:               return PRIM_TYPE_BLOCK_MODE;
        case BLOCK_MODE_OFB:               return PRIM_TYPE_BLOCK_MODE;
    }
    
    return 0;
}
