/*===-- pbkdf2.c --------------------------------------*- generic -*- C -*-===*/

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

#include "ordo/kdf/pbkdf2.h"
#include "ordo/auth/hmac.h"

/*===----------------------------------------------------------------------===*/

int kdf_pbkdf2(prim_t hash, const void *params,
               const void *pwd, size_t pwd_len,
               const void *salt, size_t salt_len,
               uintmax_t iterations,
               void *out, size_t out_len)
{
    int err;

    unsigned char buf[HASH_DIGEST_LEN], feedback[HASH_DIGEST_LEN];
    struct HMAC_CTX ctx, cst;
    size_t digest_len;

    /* The output counter is a 32-bit counter which for some reason starts
     * at 1, putting an upper bound on the maximum output length allowed. */
    uint32_t counter = 1;

    if (!pwd_len || !iterations || !out_len) return ORDO_ARG;

    if (prim_type(hash) != PRIM_TYPE_HASH)
        return ORDO_ARG;

    digest_len = digest_length(hash);

    /* This HMAC initialization need be done only once, because for each
     * iteration the key is always the same (the password). Thanks to
     * the design of HMAC, most of the work can then be precomputed. */
    if ((err = hmac_init(&cst, pwd, pwd_len, hash, params))) return err;

    while (out_len)
    {
        uint32_t ctr_endian = tobe32(counter); /* Big endian counter */
        size_t i;

        ++counter;
        ctx = cst;

        hmac_update(&ctx, salt, salt_len);
        hmac_update(&ctx, &ctr_endian, sizeof(uint32_t));

        /* We copy the first iteration result into the "feedback" buffer which
         * is used to store the previous iteration result for the next one. */
        if ((err = hmac_final(&ctx, feedback))) return err;
        memcpy(buf, feedback, digest_len);

        for (i = 1; i < iterations; ++i)
        {
            ctx = cst;

            /* Next iteration: Ui+1 = PRF(Ui). */
            hmac_update(&ctx, feedback, digest_len);
            if ((err = hmac_final(&ctx, feedback))) return err;

            /* U1 ^ U2 ^ ... ^ Ui accumulation. */
            xor_buffer(buf, feedback, digest_len);
        }

        /* Copy this block into the output buffer (handle truncation). Note
         * this ensures that even if something goes wrong at any point, the
         * user-provided buffer will only ever contain either indeterminate
         * data or valid data, and no intermediate, sensitive information. */
        memcpy(out, buf, out_len >= digest_len ? digest_len : out_len);
        out_len -= out_len >= digest_len ? digest_len : out_len;
        out = offset(out, digest_len);

        /* Maximum output length reached! */
        if ((counter == 0) && out_len)
            return ORDO_ARG;
    }

    return ORDO_SUCCESS;
}
