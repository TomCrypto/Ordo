/* Handles code related to symmetric block ciphers and block cipher modes of operation. */
#include <enc/enc_block.h>

#include <common/identification.h>
#include <common/ordo_errors.h>
#include <common/secure_mem.h>

#include <enc/block_cipher_modes/ecb.h>
#include <enc/block_cipher_modes/cbc.h>
#include <enc/block_cipher_modes/ctr.h>
#include <enc/block_cipher_modes/cfb.h>
#include <enc/block_cipher_modes/ofb.h>

/******************************************************************************/

/*! \brief Block cipher mode of operation context.
 *
 * This structure describes a block cipher mode of operation context. It is used by encryption modes of operation to
 * maintain their state across function calls. It should never be modified outside of these functions. */
struct ENC_BLOCK_CTX
{
    /*! The block cipher to use with the mode. */
    struct BLOCK_CIPHER *cipher;
    /*! The block cipher mode of operation to use. */
    struct BLOCK_MODE *mode;
    /*! The block cipher's low-level context. */
    void *cipher_ctx;
    /*! The mode of operation's low-level context. */
    void *mode_ctx;
};

/* This function returns an initialized block cipher encryption context using a specific primitive and mode of
 * operation. Note this function uses a fall-through construction to ensure no memory is leaked in case of failure. */
struct ENC_BLOCK_CTX* enc_block_alloc(struct BLOCK_CIPHER* cipher, struct BLOCK_MODE* mode)
{
    /* Allocate the encryption context. */
    struct ENC_BLOCK_CTX* ctx = secure_alloc(sizeof(struct ENC_BLOCK_CTX));
    if (ctx)
    {
        ctx->mode = mode;
        ctx->cipher = cipher;
        /* Create the cipher context. */
        if ((ctx->cipher_ctx = block_cipher_alloc(cipher)))
        {
            /* Create the mode context. */
            if ((ctx->mode_ctx = block_mode_alloc(mode, ctx->cipher, ctx->cipher_ctx))) return ctx;
            block_cipher_free(ctx->cipher, ctx->cipher_ctx);
        }
        secure_free(ctx, sizeof(struct ENC_BLOCK_CTX));
    };

    /* Fail, return zero. */
    return 0;
}

/* This function returns an initialized block cipher encryption context with the provided parameters. */
int enc_block_init(struct ENC_BLOCK_CTX* ctx, void* key, size_t keySize, void* iv, int dir, void* cipherParams, void* modeParams)
{
    /* Initialize the cipher context. */
    int error = block_cipher_init(ctx->cipher, ctx->cipher_ctx, key, keySize, cipherParams);
    if (error < ORDO_SUCCESS) return error;

    /* Initialize the encryption mode context. */
    return block_mode_init(ctx->mode, ctx->mode_ctx, ctx->cipher, ctx->cipher_ctx, iv, dir, modeParams);
}

/* This function encrypts data using the passed block cipher encryption context. If decrypt is true, the cipher will decrypt instead. */
void enc_block_update(struct ENC_BLOCK_CTX* ctx, void* in, size_t inlen, void* out, size_t* outlen)
{
    block_mode_update(ctx->mode, ctx->mode_ctx, ctx->cipher, ctx->cipher_ctx, in, inlen, out, outlen);
}

/* This function finalizes a block cipher encryption context. */
int enc_block_final(struct ENC_BLOCK_CTX* ctx, void* out, size_t* outlen)
{
    return block_mode_final(ctx->mode, ctx->mode_ctx, ctx->cipher, ctx->cipher_ctx, out, outlen);
}

/* This function frees an initialized block cipher encryption context. */
void enc_block_free(struct ENC_BLOCK_CTX* ctx)
{
    /* Free the block cipher mode context. */
    block_mode_free(ctx->mode, ctx->mode_ctx, ctx->cipher, ctx->cipher_ctx);

    /* Free the cipher context. */
    block_cipher_free(ctx->cipher, ctx->cipher_ctx);

    /* Free the context. */
    secure_free(ctx, sizeof(struct ENC_BLOCK_CTX));
}
