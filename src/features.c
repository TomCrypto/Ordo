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

#include "ordo/common/limits.h"
#include "ordo/primitives/block_modes.h"
#include "ordo/primitives/block_ciphers.h"
#include "ordo/primitives/stream_ciphers.h"
#include "ordo/primitives/hash_functions.h"

#if WITH_ECB
#include "ordo/primitives/block_modes/ecb.h"
int ecb_limits(prim_t cipher, struct BLOCK_MODE_LIMITS *limits)
{
    if (prim_type(cipher) != PRIM_TYPE_BLOCK)
        return ORDO_ARG;

    limits->iv_min = 0;
    limits->iv_max = 0;
    limits->iv_mul = 1;

    return ORDO_SUCCESS;
}
#endif

#if WITH_CBC
#include "ordo/primitives/block_modes/cbc.h"
int cbc_limits(prim_t cipher, struct BLOCK_MODE_LIMITS *limits)
{
    struct BLOCK_LIMITS block_lims;
    int err;

    if (prim_type(cipher) != PRIM_TYPE_BLOCK)
        return ORDO_ARG;

    if ((err = block_limits(cipher, &block_lims)))
        return err;

    limits->iv_min = block_lims.block_size;
    limits->iv_max = block_lims.block_size;
    limits->iv_mul = 1;

    return ORDO_SUCCESS;
}
#endif

#if WITH_CTR
#include "ordo/primitives/block_modes/ctr.h"
int ctr_limits(prim_t cipher, struct BLOCK_MODE_LIMITS *limits)
{
    struct BLOCK_LIMITS block_lims;
    int err;

    if (prim_type(cipher) != PRIM_TYPE_BLOCK)
        return ORDO_ARG;

    if ((err = block_limits(cipher, &block_lims)))
        return err;

    /* Assertion: block_limits.block_size >= 64 bits */

    limits->iv_min = block_lims.block_size - bits(64);
    limits->iv_max = block_lims.block_size - bits(64);
    limits->iv_mul = 1;

    return ORDO_SUCCESS;
}
#endif

#if WITH_CFB
#include "ordo/primitives/block_modes/cfb.h"
int cfb_limits(prim_t cipher, struct BLOCK_MODE_LIMITS *limits)
{
    struct BLOCK_LIMITS block_lims;
    int err;

    if (prim_type(cipher) != PRIM_TYPE_BLOCK)
        return ORDO_ARG;

    if ((err = block_limits(cipher, &block_lims)))
        return err;

    limits->iv_min = block_lims.block_size;
    limits->iv_max = block_lims.block_size;
    limits->iv_mul = 1;

    return ORDO_SUCCESS;
}
#endif

#if WITH_OFB
#include "ordo/primitives/block_modes/ofb.h"
int ofb_limits(prim_t cipher, struct BLOCK_MODE_LIMITS *limits)
{
    struct BLOCK_LIMITS block_lims;
    int err;

    if (prim_type(cipher) != PRIM_TYPE_BLOCK)
        return ORDO_ARG;

    if ((err = block_limits(cipher, &block_lims)))
        return err;

    limits->iv_min = block_lims.block_size;
    limits->iv_max = block_lims.block_size;
    limits->iv_mul = 1;

    return ORDO_SUCCESS;
}
#endif

#if WITH_MD5
#include "ordo/primitives/hash_functions/md5.h"
int md5_limits(struct HASH_LIMITS *limits)
{
    limits->block_size = bits(512);
    limits->digest_len = bits(128);

    return ORDO_SUCCESS;
}
#endif

#if WITH_SHA1
#include "ordo/primitives/hash_functions/sha1.h"
int sha1_limits(struct HASH_LIMITS *limits)
{
    limits->block_size = bits(512);
    limits->digest_len = bits(160);

    return ORDO_SUCCESS;
}
#endif

#if WITH_SHA256
#include "ordo/primitives/hash_functions/sha256.h"
int sha256_limits(struct HASH_LIMITS *limits)
{
    limits->block_size = bits(512);
    limits->digest_len = bits(256);

    return ORDO_SUCCESS;
}
#endif

#if WITH_SKEIN256
#include "ordo/primitives/hash_functions/skein256.h"
int skein256_limits(struct HASH_LIMITS *limits)
{
    limits->block_size = bits(256);
    limits->digest_len = bits(256);

    return ORDO_SUCCESS;
}
#endif

#if WITH_RC4
#include "ordo/primitives/stream_ciphers/rc4.h"
int rc4_limits(struct STREAM_LIMITS *limits)
{
    limits->key_min = bits(40);
    limits->key_max = bits(2048);
    limits->key_mul = 1;

    return ORDO_SUCCESS;
}
#endif

#if WITH_AES
#include "ordo/primitives/block_ciphers/aes.h"
int aes_limits(struct BLOCK_LIMITS *limits)
{
    limits->block_size = bits(128);
    limits->key_min = bits(128);
    limits->key_max = bits(256);
    limits->key_mul = bits(64);

    return ORDO_SUCCESS;
}
#endif

#if WITH_NULLCIPHER
#include "ordo/primitives/block_ciphers/nullcipher.h"
int nullcipher_limits(struct BLOCK_LIMITS *limits)
{
    limits->block_size = bits(128);
    limits->key_min = bits(0);
    limits->key_max = bits(0);
    limits->key_mul = 1;

    return ORDO_SUCCESS;
}
#endif

#if WITH_THREEFISH256
#include "ordo/primitives/block_ciphers/threefish256.h"
int threefish256_limits(struct BLOCK_LIMITS *limits)
{
    limits->block_size = bits(256);
    limits->key_min = bits(256);
    limits->key_max = bits(256);
    limits->key_mul = 1;

    return ORDO_SUCCESS;
}
#endif

/*===----------------------------------------------------------------------===*/

#include "ordo/digest/digest.h"
size_t digest_length(prim_t hash)
{
    struct HASH_LIMITS limits;

    return (!hash_limits(hash, &limits)) ? limits.digest_len : 0;
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
