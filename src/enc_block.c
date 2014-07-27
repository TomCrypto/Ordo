/*===-- enc_block.c -----------------------------------*- generic -*- C -*-===*/

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

#include "ordo/enc/enc_block.h"

/*===----------------------------------------------------------------------===*/

#ifdef OPAQUE
struct ENC_BLOCK_CTX
{
    struct BLOCK_STATE cipher;
    struct BLOCK_MODE_STATE mode;
};
#endif

/*===----------------------------------------------------------------------===*/

int enc_block_init(struct ENC_BLOCK_CTX *ctx,
                   const void *key, size_t key_len,
                   const void *iv, size_t iv_len,
                   int direction,
                   prim_t cipher, const void *cipher_params,
                   prim_t mode, const void *mode_params)
{
    int err = block_init(&ctx->cipher,
                         key, key_len,
                         cipher, cipher_params);

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
    block_final(&ctx->cipher);
    return block_mode_final(&ctx->mode, &ctx->cipher,
                            out, out_len);
}

size_t enc_block_key_len(prim_t cipher,
                         size_t key_len)
{
    return block_query(cipher, KEY_LEN_Q, key_len);
}

size_t enc_block_iv_len(prim_t cipher,
                        prim_t mode,
                        size_t iv_len)
{
    return block_mode_query(mode, cipher, IV_LEN_Q, iv_len);
}
