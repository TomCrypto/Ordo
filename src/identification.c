/*===-- identification.c ------------------------------*- generic -*- C -*-===*/

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

/*===----------------------------------------------------------------------===*/

struct NAMED_PRIMITIVE
{
    const char *name;
    int primitive;
};

static const struct NAMED_PRIMITIVE list[] =
{
    { "MD5", HASH_MD5 },
    { "SHA-256", HASH_SHA256 },
    { "Skein-256", HASH_SKEIN256 },
    { "RC4", STREAM_RC4 },
    { "AES", BLOCK_AES },
    { "Threefish-256", BLOCK_THREEFISH256 },
    { "NullCipher", BLOCK_NULLCIPHER },
    { "ECB", BLOCK_MODE_ECB },
    { "CBC", BLOCK_MODE_CBC },
    { "CTR", BLOCK_MODE_CTR },
    { "CFB", BLOCK_MODE_CFB },
    { "OFB", BLOCK_MODE_OFB }
};

const char *prim_name(int prim)
{
    size_t t;
    
    for (t = 0; t < sizeof(list) / sizeof(struct NAMED_PRIMITIVE); ++t)
        if (list[t].primitive == prim) return list[t].name;
    
    return 0;
}

int prim_from_name(const char *name)
{
    size_t t;
    
    for (t = 0; t < sizeof(list) / sizeof(struct NAMED_PRIMITIVE); ++t)
        if (!strcmp(list[t].name, name)) return list[t].primitive;
    
    return 0;
}

prim_t prim_available(prim_t prim)
{
    const int *p;
    
    for (p = prim_type(PRIM_TYPE_HASH); *p; ++p)
        if (prim == *p) return 1;
    
    for (p = prim_type(PRIM_TYPE_STREAM); *p; ++p)
        if (prim == *p) return 1;

    for (p = prim_type(PRIM_TYPE_BLOCK); *p; ++p)
        if (prim == *p) return 1;

    for (p = prim_type(PRIM_TYPE_BLOCK_MODE); *p; ++p)
        if (prim == *p) return 1;

    return 0;
}

static const int hash_list[] =
{
    #ifdef USING_MD5
    HASH_MD5,
    #endif
    #ifdef USING_SHA256
    HASH_SHA256,
    #endif
    #ifdef USING_SKEIN256
    HASH_SKEIN256,
    #endif
    0
};

static const int stream_list[] =
{
    #ifdef USING_RC4
    STREAM_RC4,
    #endif
    0
};

static const int block_list[] =
{
    #ifdef USING_AES
    BLOCK_AES,
    #endif
    #ifdef USING_THREEFISH256
    BLOCK_THREEFISH256,
    #endif
    #ifdef USING_NULLCIPHER
    BLOCK_NULLCIPHER,
    #endif
    0
};

static const int block_mode_list[] =
{
    #ifdef USING_ECB
    BLOCK_MODE_ECB,
    #endif
    #ifdef USING_CBC
    BLOCK_MODE_CBC,
    #endif
    #ifdef USING_CTR
    BLOCK_MODE_CTR,
    #endif
    #ifdef USING_CFB
    BLOCK_MODE_CFB,
    #endif
    #ifdef USING_OFB
    BLOCK_MODE_OFB,
    #endif
    0
};

const int *prim_type(int type)
{
    switch (type)
    {
        case PRIM_TYPE_HASH:
            return hash_list;
    
        case PRIM_TYPE_STREAM:
            return stream_list;
        
        case PRIM_TYPE_BLOCK:
            return block_list;
        
        case PRIM_TYPE_BLOCK_MODE:
            return block_mode_list;
    }
    
    return 0;
}

int prim_is_type(int prim, int type)
{
    const int *p;
    
    for (p = prim_type(type); *p; ++p)
        if (prim == *p) return 1;
    
    return 0;
}
