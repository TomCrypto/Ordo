/*===-- ordo.c ----------------------------------------*- generic -*- C -*-===*/

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

#include "ordo.h"

/*===----------------------------------------------------------------------===*/

int ordo_enc_block(prim_t cipher, const void *cipher_params,
                   prim_t mode, const void *mode_params,
                   int direction,
                   const void *key, size_t key_len,
                   const void *iv, size_t iv_len,
                   const void *in,size_t in_len,
                   void* out, size_t *out_len)
{
    struct ENC_BLOCK_CTX ctx;
    int err = ORDO_SUCCESS;
    size_t end_pos = 0;

    if ((err = enc_block_init(&ctx,
                              key, key_len,
                              iv, iv_len,
                              direction,
                              cipher, cipher_params,
                              mode, mode_params)))
        return err;

    enc_block_update(&ctx, in, in_len, out, out_len);
    end_pos += *out_len;

    if ((err = enc_block_final(&ctx,
                               offset(out, end_pos),
                               out_len)))
        return err;

    *out_len += end_pos;

    return err;
}

int ordo_enc_stream(prim_t cipher, const void *params,
                    const void *key, size_t key_len,
                    void *buffer, size_t len)
{
    int err;

    struct ENC_STREAM_CTX ctx;
    
    if ((err = enc_stream_init(&ctx, key, key_len, cipher, params)))
        return err;

    enc_stream_update(&ctx, buffer, len);
    enc_stream_final(&ctx);

    return ORDO_SUCCESS;
}

int ordo_digest(prim_t hash, const void *params,
                const void *in, size_t len,
                void *digest)
{
    int err;

    struct DIGEST_CTX ctx;

    if ((err = digest_init(&ctx, hash, params)))
        return err;

    digest_update(&ctx, in, len);
    digest_final(&ctx, digest);

    return ORDO_SUCCESS;
}

int ordo_hmac(prim_t hash, const void *params,
              const void *key, size_t key_len,
              const void *in, size_t len,
              void *fingerprint)
{
    int err;

    struct HMAC_CTX ctx;

    if ((err = hmac_init(&ctx, key, key_len, hash, params)))
        return err;

    hmac_update(&ctx, in, len);

    if ((err = hmac_final(&ctx, fingerprint)))
        return err;

    return ORDO_SUCCESS;
}
