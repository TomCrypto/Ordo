#include <primitives/primitives.h>
#include <encrypt/encrypt.h>
#include <encrypt/modes/ctr.h>

/* This is extra context space required by the CTR mode to store the counter and the amount of state not used.*/
typedef struct CTR_ENCRYPT_CONTEXT
{
    /* A buffer for the IV. */
    void* iv;
    /* The counter value. */
    unsigned char* counter;
    /* The amount of bytes of unused state remaining before the state is to be renewed. */
    size_t remaining;
} CTR_ENCRYPT_CONTEXT;

/* Shorthand macro for context casting. */
#define ctr(ctx) ((CTR_ENCRYPT_CONTEXT*)ctx)

ENCRYPT_MODE_CONTEXT* CTR_Create(ENCRYPT_MODE* mode, CIPHER_PRIMITIVE_CONTEXT* cipher)
{
    /* Allocate the context and extra buffers in it. */
    ENCRYPT_MODE_CONTEXT* ctx = salloc(sizeof(ENCRYPT_MODE_CONTEXT));
    if (ctx)
    {
        ctx->mode = mode;
        ctx->ctx = salloc(sizeof(CTR_ENCRYPT_CONTEXT));
        if (ctx->ctx)
        {
            ctr(ctx->ctx)->iv = salloc(cipher->primitive->szBlock);
            if (ctr(ctx->ctx)->iv)
            {
                ctr(ctx->ctx)->counter = salloc(cipher->primitive->szBlock);
                if (ctr(ctx->ctx)->counter)
                {
                    ctr(ctx->ctx)->remaining = 0;
                    return ctx;
                }
                sfree(ctr(ctx->ctx)->iv, cipher->primitive->szBlock);
            }
            sfree(ctx->ctx, sizeof(CTR_ENCRYPT_CONTEXT));
        }
        sfree(ctx, sizeof(ENCRYPT_MODE_CONTEXT));
    }

    /* Allocation failed, return zero. */
    return 0;
}

int CTR_Init(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, void* iv, void* params)
{
    /* Copy the IV (required) into the context IV. */
    memcpy(ctr(mode->ctx)->iv, iv, cipher->primitive->szBlock);

    /* Copy the IV into the counter. */
    memcpy(ctr(mode->ctx)->counter, ctr(mode->ctx)->iv, cipher->primitive->szBlock);

    /* Compute the initial keystream block. */
    cipher->primitive->fForward(cipher, ctr(mode->ctx)->iv, cipher->primitive->szBlock);
    ctr(mode->ctx)->remaining = cipher->primitive->szBlock;

    /* Return success. */
    return ORDO_ESUCCESS;
}

void CTR_Update(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
    /* Variable to store how much data can be processed per iteration. */
    size_t process = 0;

    /* Initialize the output size. */
    *outlen = 0;

    /* Go over the input buffer byte per byte. */
    while (inlen != 0)
    {
        /* If there is no data left in the context block, update. */
        if (ctr(mode->ctx)->remaining == 0)
        {
            /* CTR update (increment counter, copy counter into IV, encrypt IV). */
            incBuffer(ctr(mode->ctx)->counter, cipher->primitive->szBlock);
            memcpy(ctr(mode->ctx)->iv, ctr(mode->ctx)->counter, cipher->primitive->szBlock);
            cipher->primitive->fForward(cipher, ctr(mode->ctx)->iv, cipher->primitive->szBlock);
            ctr(mode->ctx)->remaining = cipher->primitive->szBlock;
        }

        /* Compute the amount of data to process. */
        process = (inlen < ctr(mode->ctx)->remaining) ? inlen : ctr(mode->ctx)->remaining;

        /* Process this amount of data. */
        memmove(out, in, process);
        xorBuffer(out, (unsigned char*)ctr(mode->ctx)->iv + cipher->primitive->szBlock - ctr(mode->ctx)->remaining, process);
        ctr(mode->ctx)->remaining -= process;
        (*outlen) += process;
        inlen -= process;
        out += process;
        in += process;
    }
}

int CTR_Final(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* out, size_t* outlen)
{
    /* Write output size if applicable. */
    if (outlen != 0) *outlen = 0;

    /* Return success. */
    return ORDO_ESUCCESS;
}

void CTR_Free(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher)
{
    /* Free context space. */
    sfree(ctr(mode->ctx)->counter, cipher->primitive->szBlock);
    sfree(ctr(mode->ctx)->iv, cipher->primitive->szBlock);
    sfree(mode->ctx, sizeof(CTR_ENCRYPT_CONTEXT));
    sfree(mode, sizeof(ENCRYPT_MODE_CONTEXT));
}

/* Fills a ENCRYPT_MODE struct with the correct information. */
void CTR_SetMode(ENCRYPT_MODE* mode)
{
    ENCRYPT_MAKEMODE(mode, CTR_Create, CTR_Init, CTR_Update, CTR_Update, CTR_Final, CTR_Final, CTR_Free, "CTR");
}
