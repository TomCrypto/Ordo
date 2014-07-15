/*===-- hkdf.c ----------------------------------------*- generic -*- C -*-===*/

#include "ordo/kdf/hkdf.h"

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

#include "ordo/auth/hmac.h"

/*===----------------------------------------------------------------------===*/

int kdf_hkdf(prim_t hash, const void *params,
             const void *key, size_t key_len,
             const void *salt, size_t salt_len,
             const void *info, size_t info_len,
             void *out, size_t out_len)
{
    int err;

    const size_t digest_len = digest_length(hash);
    unsigned char buf[HASH_DIGEST_LEN] = {0};
    unsigned char prk[HASH_DIGEST_LEN];
    struct HMAC_CTX ctx, cst;
    uint8_t counter = 1;

    if (!key_len || !out_len) return ORDO_ARG;

    if (!salt_len)
    {
        if ((err = hmac_init(&ctx, buf, digest_len, hash, params)))
            return err;
    }
    else
    {
        if ((err = hmac_init(&ctx, salt, salt_len, hash, params)))
            return err;
    }

    hmac_update(&ctx, key, key_len);
    if ((err = hmac_final(&ctx, prk)))
        return err;

    if ((err = hmac_init(&cst, prk, digest_len, hash, params)))
        return err;

    while (out_len)
    {
        /* Maximum output length reached! */
        if (counter == 0) return ORDO_ARG;

        ctx = cst;

        /* First buffer ("T(0)") is the empty string (zero length) */
        hmac_update(&ctx, buf, (counter == 1) ? 0 : digest_len);
        hmac_update(&ctx, info, info_len);
        hmac_update(&ctx, &counter, 1);

        if ((err = hmac_final(&ctx, buf)))
            return err;

        memcpy(out, buf, out_len >= digest_len ? digest_len : out_len);
        out_len -= out_len >= digest_len ? digest_len : out_len;
        out = offset(out, digest_len);

        ++counter;
    }

    return ORDO_SUCCESS;
}
