/*===-- enc_block.c -----------------------------------*- generic -*- C -*-===*/

#include "ordo/enc/enc_block.h"

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

/*===----------------------------------------------------------------------===*/

int enc_block_init(struct ENC_BLOCK_CTX *ctx,
                   const void *key, size_t key_len,
                   const void *iv, size_t iv_len,
                   int direction,
                   enum BLOCK_CIPHER cipher,
                   const void *cipher_params,
                   enum BLOCK_MODE mode,
                   const void *mode_params)
{
    int err = block_cipher_init(&ctx->cipher,
                                key, key_len,
                                cipher,
                                cipher_params);

    if (err != ORDO_SUCCESS) return err;

    return block_mode_init(&ctx->mode, &ctx->cipher,
                           iv, iv_len, direction,
                           mode, mode_params);
}

void enc_block_update(struct ENC_BLOCK_CTX *ctx,
                      const void *in, size_t in_len,
                      void *out, size_t *out_len)
{
    block_mode_update(&ctx->mode, &ctx->cipher,
                      in, in_len, out, out_len);
}

int enc_block_final(struct ENC_BLOCK_CTX *ctx,
                    void *out, size_t *out_len)
{
    block_cipher_final(&ctx->cipher);
    return block_mode_final(&ctx->mode, &ctx->cipher,
                            out, out_len);
}

void enc_block_copy(struct ENC_BLOCK_CTX *dst,
                    const struct ENC_BLOCK_CTX *src)
{
    *dst = *src;
}

size_t enc_block_key_len(enum BLOCK_CIPHER cipher,
                         size_t key_len)
{
    return block_cipher_query(cipher, KEY_LEN_Q, key_len);
}

size_t enc_block_iv_len(enum BLOCK_CIPHER cipher,
                        enum BLOCK_MODE mode,
                        size_t iv_len)
{
    return block_mode_query(mode, cipher, IV_LEN_Q, iv_len);
}
