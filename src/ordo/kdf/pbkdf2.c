#include "ordo/kdf/pbkdf2.h"

#include "ordo/internal/endianness.h"
#include "ordo/internal/mem.h"

#include "ordo/common/errors.h"
#include "ordo/common/utils.h"

#include "ordo/auth/hmac.h"

#include <string.h>

/******************************************************************************/

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

    struct HMAC_CTX *ctx = hmac_alloc(hash);
    struct HMAC_CTX *cst = hmac_alloc(hash);

    void *buf = mem_alloc(digest_len);
    void *feedback = mem_alloc(digest_len);

    /* The output counter is a 32-bit counter which for some reason starts at
     * 1 which puts an upper bound on the maximum output length allowed. */
    if ((!out_len) || (!iterations) || (t_max > (size_t)UINT32_MAX - 2))
    {
        err = ORDO_ARG;
        goto ret;
    }

    if ((!ctx) || (!cst) || (!buf) || (!feedback))
    {
        err = ORDO_ALLOC;
        goto ret;
    }

    for (t = 0; t < t_max + 1; ++t)
    {
        uint32_t counter = htobe32(t + 1); /* Big-endian. */

        if ((err = hmac_init(ctx,
                             password, password_len,
                             params))) goto ret;

        hmac_update(ctx, salt, salt_len);
        hmac_update(ctx, &counter, sizeof(uint32_t));

        /* We copy the first iteration result into the "feedback" buffer which
         * is used to store the previous iteration result for the next one. */
        if ((err = hmac_final(ctx, feedback))) goto ret;
        memcpy(buf, feedback, digest_len);

        /* This HMAC initialization need be done only once, because for each
         * iteration the key is always the same (the password). Thanks to
         * the design of HMAC, most of the work can then be precomputed. */
        if ((err = hmac_init(cst,
                             password, password_len,
                             params))) goto ret;

        for (i = 1; i < iterations; ++i)
        {
            /* Next iteration: Ui+1 = PRF(Ui). */
            hmac_copy(ctx, cst);
            hmac_update(ctx, feedback, digest_len);
            if ((err = hmac_final(ctx, feedback))) goto ret;

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

ret:
    mem_free(feedback);
    mem_free(buf);
    hmac_free(ctx);
    hmac_free(cst);
    return err;
}
