#include "ordo.h"

#include "internal/mem.h"

/******************************************************************************/

int ordo_init()
{
    return mem_init();
}

int ordo_enc_block(const struct BLOCK_CIPHER* cipher,
                   const void *cipher_params,
                   const struct BLOCK_MODE* mode,
                   const void *mode_params,
                   int direction,
                   const void *key, size_t key_len,
                   const void *iv, size_t iv_len,
                   const void *in,size_t in_len,
                   void* out, size_t *out_len)
{
    int err = ORDO_ALLOC;
    size_t end_pos = 0;

    struct ENC_BLOCK_CTX* ctx = enc_block_alloc(cipher, mode);
    if (!ctx) goto fail;

    if ((err = enc_block_init(ctx,
                              key, key_len,
                              iv, iv_len,
                              direction,
                              cipher_params,
                              mode_params))) goto fail;

    enc_block_update(ctx, in, in_len, out, out_len);
    end_pos += *out_len;

    if ((err = enc_block_final(ctx,
                               (unsigned char*)out + end_pos,
                               out_len))) goto fail;
    *out_len += end_pos;

fail:
    enc_block_free(ctx);
    return err;
}

int ordo_enc_stream(const struct STREAM_CIPHER *cipher, const void *params,
                    const void *key, size_t key_len,
                    void *buffer, size_t len)
{
    int err = ORDO_ALLOC;

    struct ENC_STREAM_CTX* ctx = enc_stream_alloc(cipher);
    if (!ctx) goto fail;

    if ((err = enc_stream_init(ctx, key, key_len, params))) goto fail;
    enc_stream_update(ctx, buffer, len);

fail:
    enc_stream_free(ctx);
    return err;
}

int ordo_digest(const struct HASH_FUNCTION *hash, const void *params,
                const void *in, size_t len,
                void *digest)
{
    int err = ORDO_ALLOC;

    struct DIGEST_CTX* ctx = digest_alloc(hash);
    if (!ctx) goto fail;

    if ((err = digest_init(ctx, params))) goto fail;

    digest_update(ctx, in, len);
    digest_final(ctx, digest);

fail:
    digest_free(ctx);
    return err;
}

int ordo_hmac(const struct HASH_FUNCTION *hash, const void *params,
              const void *key, size_t key_len,
              const void *in, size_t len,
              void* fingerprint)
{
    int err = ORDO_ALLOC;

    struct HMAC_CTX* ctx = hmac_alloc(hash);
    if (!ctx) goto fail;

    if ((err = hmac_init(ctx, key, key_len, params))) goto fail;

    hmac_update(ctx, in, len);

    err = hmac_final(ctx, fingerprint);

fail:
    hmac_free(ctx);
    return err;
}
