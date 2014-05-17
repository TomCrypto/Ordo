/*===-- pbkdf2.c --------------------------------------*- generic -*- C -*-===*/

#include "ordo/kdf/pbkdf2.h"

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

#include "ordo/auth/hmac.h"

/*===----------------------------------------------------------------------===*/

int pbkdf2(const struct HASH_FUNCTION *hash,
            const void *params,
            const void *password,
            size_t password_len,
            const void *salt,
            size_t salt_len,
            size_t iterations,
            void *out,
            size_t out_len)
{
    int err = ORDO_SUCCESS;

    const size_t digest_len = digest_length(hash);
    size_t i, t, t_max = out_len / digest_len;

    struct HMAC_CTX ctx, cst;
    
    // TODO: TEMPORARY - digest length buffer max size = 2048 bytes
    unsigned char buf[2048];
    unsigned char feedback[2048];

    /* The output counter is a 32-bit counter which for some reason starts
     * at 1, putting an upper bound on the maximum output length allowed. */
    if ((!out_len) || (!iterations) || (t_max > (size_t)UINT32_MAX - 2))
    {
        err = ORDO_ARG;
        return err;
    }

    for (t = 0; t < t_max + 1; ++t)
    {
        uint32_t counter = tobe32((uint32_t)(t + 1)); /* Big-endian. */

        if ((err = hmac_init(&ctx,
                             password, password_len,
                             hash, params))) return err;

        hmac_update(&ctx, salt, salt_len);
        hmac_update(&ctx, &counter, sizeof(uint32_t));

        /* We copy the first iteration result into the "feedback" buffer which
         * is used to store the previous iteration result for the next one. */
        if ((err = hmac_final(&ctx, feedback))) return err;
        memcpy(buf, feedback, digest_len);

        /* This HMAC initialization need be done only once, because for each
         * iteration the key is always the same (the password). Thanks to
         * the design of HMAC, most of the work can then be precomputed. */
        if ((err = hmac_init(&cst,
                             password, password_len,
                             hash, params))) return err;

        for (i = 1; i < iterations; ++i)
        {
            /* Next iteration: Ui+1 = PRF(Ui). */
            hmac_copy(&ctx, &cst);
            hmac_update(&ctx, feedback, digest_len);
            if ((err = hmac_final(&ctx, feedback))) return err;

            /* U1 ^ U2 ^ ... ^ Ui accumulation. */
            xor_buffer(buf, feedback, digest_len);
        }

        /* Copy this block into the output buffer (handle truncation). Note
         * this ensures that even if something goes wrong at any point, the
         * user-provided buffer will only ever contain either indeterminate
         * data or valid data, and no intermediate, sensitive information. */
        memcpy(offset(out, t * digest_len),
               buf,
               (t == t_max) ? out_len % digest_len : digest_len);
    }
    
    return err;
}
