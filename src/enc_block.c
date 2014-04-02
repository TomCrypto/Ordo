/*===-- enc_block.c -----------------------------------*- generic -*- C -*-===*/

#include "ordo/enc/enc_block.h"

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

/*===----------------------------------------------------------------------===*/

struct ENC_BLOCK_CTX
{
    const struct BLOCK_CIPHER *cipher;
    const struct BLOCK_MODE *mode;
    void *cipher_state;
    void *mode_state;
};

struct ENC_BLOCK_CTX *enc_block_alloc(const struct BLOCK_CIPHER *cipher,
                                      const struct BLOCK_MODE *mode)
{
    struct ENC_BLOCK_CTX *ctx = mem_alloc(sizeof(struct ENC_BLOCK_CTX));
    if (!ctx) goto fail;

    ctx->cipher = cipher;
    ctx->mode = mode;

    if (!(ctx->cipher_state = block_cipher_alloc(cipher))) goto fail;

    if (!(ctx->mode_state = block_mode_alloc(mode, ctx->cipher,
                                             ctx->cipher_state))) goto fail;

    return ctx;

fail:
    enc_block_free(ctx);
    return 0;
}

int enc_block_init(struct ENC_BLOCK_CTX *ctx,
                   const void *key, size_t key_len,
                   const void *iv, size_t iv_len,
                   int direction,
                   const void *cipher_params,
                   const void *mode_params)
{
    int err = block_cipher_init(ctx->cipher, ctx->cipher_state,
                                key, key_len,
                                cipher_params);

    if (err != ORDO_SUCCESS) return err;

    return block_mode_init(ctx->mode, ctx->mode_state,
                           ctx->cipher, ctx->cipher_state,
                           iv, iv_len, direction,
                           mode_params);
}

void enc_block_update(struct ENC_BLOCK_CTX *ctx,
                      const void *in, size_t in_len,
                      void *out, size_t *out_len)
{
    block_mode_update(ctx->mode, ctx->mode_state,
                      ctx->cipher, ctx->cipher_state,
                      in, in_len, out, out_len);
}

int enc_block_final(struct ENC_BLOCK_CTX *ctx,
                    void *out, size_t *out_len)
{
    block_cipher_final(ctx->cipher, ctx->cipher_state);
    return block_mode_final(ctx->mode, ctx->mode_state,
                            ctx->cipher, ctx->cipher_state,
                            out, out_len);
}

void enc_block_free(struct ENC_BLOCK_CTX *ctx)
{
    if (ctx)
    {
        block_mode_free(ctx->mode, ctx->mode_state,
                        ctx->cipher, ctx->cipher_state);

        block_cipher_free(ctx->cipher, ctx->cipher_state);
    }

    mem_free(ctx);
}

void enc_block_copy(struct ENC_BLOCK_CTX *dst,
                    const struct ENC_BLOCK_CTX *src)
{
    block_mode_copy(dst->mode, dst->cipher,
                    dst->mode_state,
                    src->mode_state);

    block_cipher_copy(dst->cipher,
                      dst->cipher_state,
                      src->cipher_state);
}

size_t enc_block_key_len(const struct BLOCK_CIPHER *cipher,
                         size_t key_len)
{
    return block_cipher_query(cipher, KEY_LEN_Q, key_len);
}

size_t enc_block_iv_len(const struct BLOCK_CIPHER *cipher,
                        const struct BLOCK_MODE *mode,
                        size_t iv_len)
{
    return block_mode_query(mode, cipher, IV_LEN_Q, iv_len);
}