/*===-- ordo.c ----------------------------------------*- generic -*- C -*-===*/

#include "ordo.h"

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

/*===----------------------------------------------------------------------===*/

int ordo_enc_block(enum BLOCK_CIPHER cipher,
                   const void *cipher_params,
                   enum BLOCK_MODE mode,
                   const void *mode_params,
                   int direction,
                   const void *key, size_t key_len,
                   const void *iv, size_t iv_len,
                   const void *in,size_t in_len,
                   void* out, size_t *out_len)
{
    int err = ORDO_SUCCESS;
    size_t end_pos = 0;
    struct ENC_BLOCK_CTX ctx;

    if ((err = enc_block_init(&ctx,
                              key, key_len,
                              iv, iv_len,
                              direction,
                              cipher, cipher_params,
                              mode, mode_params))) return err;

    enc_block_update(&ctx, in, in_len, out, out_len);
    end_pos += *out_len;

    if ((err = enc_block_final(&ctx,
                               offset(out, end_pos),
                               out_len))) return err;
    *out_len += end_pos;

    return err;
}

int ordo_enc_stream(enum STREAM_CIPHER cipher, const void *params,
                    const void *key, size_t key_len,
                    void *buffer, size_t len)
{
    int err = ORDO_SUCCESS;
    struct ENC_STREAM_CTX ctx;

    if (!(err = enc_stream_init(&ctx, key, key_len, cipher, params)))
    {
        enc_stream_update(&ctx, buffer, len);
        enc_stream_final(&ctx);
    }

    return err;
}

int ordo_digest(enum HASH_FUNCTION hash, const void *params,
                const void *in, size_t len,
                void *digest)
{
    int err = ORDO_SUCCESS;
    struct DIGEST_CTX ctx;

    if (!(err = digest_init(&ctx, hash, params)))
    {
        digest_update(&ctx, in, len);
        digest_final(&ctx, digest);
    }

    return err;
}

int ordo_hmac(enum HASH_FUNCTION hash, const void *params,
              const void *key, size_t key_len,
              const void *in, size_t len,
              void *fingerprint)
{
    int err = ORDO_SUCCESS;
    struct HMAC_CTX ctx;

    if (!(err = hmac_init(&ctx, key, key_len, hash, params)))
    {
        hmac_update(&ctx, in, len);
        err = hmac_final(&ctx, fingerprint);
    }

    return err;
}
