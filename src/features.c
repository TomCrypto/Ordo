/*===-- features.c ------------------------------------*- generic -*- C -*-===*/

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

/*===----------------------------------------------------------------------===*/

/* The purpose of this file merits an explanation. A few of the functions that
 * are declared in the library headers are always going to be identical across
 * all implementations (e.g. for a given platform/architecture/feature) either
 * by necessity or by definition. We therefore give their implementation here.
*/

/*===----------------------------------------------------------------------===*/

#include "ordo/common/query.h"

#if WITH_ECB
#include "ordo/primitives/block_modes/ecb.h"
size_t ecb_query(prim_t cipher, int query, size_t value)
{
    switch(query)
    {
        case IV_LEN_Q: return 0;
        default      : return 0;
    }
}
#endif

#if WITH_CBC
#include "ordo/primitives/block_modes/cbc.h"
size_t cbc_query(prim_t cipher, int query, size_t value)
{
    switch(query)
    {
        case IV_LEN_Q: return block_query(cipher, BLOCK_SIZE_Q, 0);
        default      : return 0;
    }
}
#endif

#if WITH_CTR
#include "ordo/primitives/block_modes/ctr.h"
size_t ctr_query(prim_t cipher, int query, size_t value)
{
    size_t block_size = block_query(cipher, BLOCK_SIZE_Q, 0);

    switch(query)
    {
        case IV_LEN_Q: return block_size - bits(64);
        default      : return 0;
    }
}
#endif

#if WITH_CFB
#include "ordo/primitives/block_modes/cfb.h"
size_t cfb_query(prim_t cipher, int query, size_t value)
{
    switch(query)
    {
        case IV_LEN_Q: return block_query(cipher, BLOCK_SIZE_Q, 0);
        default      : return 0;
    }
}
#endif

#if WITH_OFB
#include "ordo/primitives/block_modes/ofb.h"
size_t ofb_query(prim_t cipher, int query, size_t value)
{
    switch(query)
    {
        case IV_LEN_Q: return block_query(cipher, BLOCK_SIZE_Q, 0);
        default      : return 0;
    }
}
#endif

#if WITH_MD5
#include "ordo/primitives/hash_functions/md5.h"
size_t md5_query(int query, size_t value)
{
    switch(query)
    {
        case BLOCK_SIZE_Q: return bits(512);
        case DIGEST_LEN_Q: return bits(128);

        default: return 0;
    }
}
#endif

#if WITH_SHA1
#include "ordo/primitives/hash_functions/sha1.h"
size_t sha1_query(int query, size_t value)
{
    switch(query)
    {
        case BLOCK_SIZE_Q: return bits(512);
        case DIGEST_LEN_Q: return bits(160);

        default: return 0;
    }
}
#endif

#if WITH_SHA256
#include "ordo/primitives/hash_functions/sha256.h"
size_t sha256_query(int query, size_t value)
{
    switch(query)
    {
        case BLOCK_SIZE_Q: return bits(512);
        case DIGEST_LEN_Q: return bits(256);

        default: return 0;
    }
}
#endif

#if WITH_SKEIN256
#include "ordo/primitives/hash_functions/skein256.h"
size_t skein256_query(int query, size_t value)
{
    switch(query)
    {
        case BLOCK_SIZE_Q: return bits(256);
        case DIGEST_LEN_Q: return bits(256);
        default          : return 0;
    }
}
#endif

#if WITH_RC4
#include "ordo/primitives/stream_ciphers/rc4.h"
size_t rc4_query(int query, size_t key_len)
{
    switch (query)
    {
        case KEY_LEN_Q:
            if (key_len < bits(40))
                return bits(40);
            if (key_len > bits(2048))
                return bits(2048);
            return key_len;
        default:
            return 0;
    }
}
#endif

#if WITH_AES
#include "ordo/primitives/block_ciphers/aes.h"
size_t aes_query(int query, size_t value)
{
    switch(query)
    {
        case BLOCK_SIZE_Q:
            return bits(128);
        case KEY_LEN_Q:
            if (value <= 16)
                return bits(128);
            if (value <= 24)
                return bits(192);
            return bits(256);
        default:
            return 0;
    }
}
#endif

#if WITH_NULLCIPHER
#include "ordo/primitives/block_ciphers/nullcipher.h"
size_t nullcipher_query(int query, size_t value)
{
    switch(query)
    {
        case BLOCK_SIZE_Q: return bits(128);
        case KEY_LEN_Q   : return bits(0);
        default          : return 0;
    }
}
#endif

#if WITH_THREEFISH256
#include "ordo/primitives/block_ciphers/threefish256.h"
size_t threefish256_query(int query, size_t value)
{
    switch(query)
    {
        case BLOCK_SIZE_Q: return bits(256);
        case KEY_LEN_Q   : return bits(256);
        default          : return 0;
    }
}
#endif

/*===----------------------------------------------------------------------===*/

#include "ordo/digest/digest.h"
size_t digest_length(prim_t hash)
{
    return hash_query(hash, DIGEST_LEN_Q, 0);
}

/*===----------------------------------------------------------------------===*/

#if WITH_ECB
#include "ordo/primitives/block_modes/ecb.h"
size_t ecb_bsize(void)
{
    return sizeof(struct ECB_STATE);
}
#endif

#if WITH_CBC
#include "ordo/primitives/block_modes/cbc.h"
size_t cbc_bsize(void)
{
    return sizeof(struct CBC_STATE);
}
#endif

#if WITH_CTR
#include "ordo/primitives/block_modes/ctr.h"
size_t ctr_bsize(void)
{
    return sizeof(struct CTR_STATE);
}
#endif

#if WITH_CFB
#include "ordo/primitives/block_modes/cfb.h"
size_t cfb_bsize(void)
{
    return sizeof(struct CFB_STATE);
}
#endif

#if WITH_OFB
#include "ordo/primitives/block_modes/ofb.h"
size_t ofb_bsize(void)
{
    return sizeof(struct OFB_STATE);
}
#endif

#if WITH_AES
#include "ordo/primitives/block_ciphers/aes.h"
size_t aes_bsize(void)
{
    return sizeof(struct AES_STATE);
}
#endif

#if WITH_NULLCIPHER
#include "ordo/primitives/block_ciphers/nullcipher.h"
size_t nullcipher_bsize(void)
{
    return sizeof(struct NULLCIPHER_STATE);
}
#endif

#if WITH_THREEFISH256
#include "ordo/primitives/block_ciphers/threefish256.h"
size_t threefish256_bsize(void)
{
    return sizeof(struct THREEFISH256_STATE);
}
#endif

#if WITH_RC4
#include "ordo/primitives/stream_ciphers/rc4.h"
size_t rc4_bsize(void)
{
    return sizeof(struct RC4_STATE);
}
#endif

#if WITH_MD5
#include "ordo/primitives/hash_functions/md5.h"
size_t md5_bsize(void)
{
    return sizeof(struct MD5_STATE);
}
#endif

#if WITH_SHA1
#include "ordo/primitives/hash_functions/sha1.h"
size_t sha1_bsize(void)
{
    return sizeof(struct SHA1_STATE);
}
#endif

#if WITH_SHA256
#include "ordo/primitives/hash_functions/sha256.h"
size_t sha256_bsize(void)
{
    return sizeof(struct SHA256_STATE);
}
#endif

#if WITH_SKEIN256
#include "ordo/primitives/hash_functions/skein256.h"
size_t skein256_bsize(void)
{
    return sizeof(struct SKEIN256_STATE);
}
#endif

#include "ordo/primitives/block_ciphers.h"
size_t block_bsize(void)
{
    return sizeof(struct BLOCK_STATE);
}

#include "ordo/primitives/block_modes.h"
size_t block_mode_bsize(void)
{
    return sizeof(struct BLOCK_MODE_STATE);
}

#include "ordo/primitives/hash_functions.h"
size_t hash_bsize(void)
{
    return sizeof(struct HASH_STATE);
}

#include "ordo/primitives/stream_ciphers.h"
size_t stream_bsize(void)
{
    return sizeof(struct STREAM_STATE);
}

#include "ordo/enc/enc_block.h"
size_t enc_block_bsize(void)
{
    return sizeof(struct ENC_BLOCK_CTX);
}

#include "ordo/auth/hmac.h"
size_t hmac_bsize(void)
{
    return sizeof(struct HMAC_CTX);
}
