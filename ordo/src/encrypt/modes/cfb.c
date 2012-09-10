#include <primitives/primitives.h>
#include <encrypt/encrypt.h>
#include <encrypt/modes/cfb.h>

/* This is extra context space required by the CFB mode to store the amount of state not used.*/
typedef struct CFB_ENCRYPT_CONTEXT
{
    /* A buffer for the IV. */
    void* iv;
    /* The amount of bytes of unused state remaining before the state is to be renewed. */
    size_t remaining;
} CFB_ENCRYPT_CONTEXT;

/* Shorthand macro for context casting. */
#define cfb(ctx) ((CFB_ENCRYPT_CONTEXT*)ctx)

ENCRYPT_MODE_CONTEXT* CFB_Create(ENCRYPT_MODE* mode, CIPHER_PRIMITIVE_CONTEXT* cipher)
{
    /* Allocate the context and extra buffers in it. */
    ENCRYPT_MODE_CONTEXT* ctx = salloc(sizeof(ENCRYPT_MODE_CONTEXT));
    if (ctx)
    {
        ctx->mode = mode;
        ctx->ctx = salloc(sizeof(CFB_ENCRYPT_CONTEXT));
        if (ctx->ctx)
        {
            cfb(ctx->ctx)->iv = salloc(cipher->primitive->szBlock);
            if (cfb(ctx->ctx)->iv)
            {
                cfb(ctx->ctx)->remaining = 0;
                return ctx;
            }
            sfree(ctx->ctx, sizeof(CFB_ENCRYPT_CONTEXT));
        }
        sfree(ctx, sizeof(ENCRYPT_MODE_CONTEXT));
    }

    /* Allocation failed, return zero. */
    return 0;
}

int CFB_Init(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, void* iv, void* params)
{
    /* Copy the IV (required) into the context IV. */
    memcpy(cfb(mode->ctx)->iv, iv, cipher->primitive->szBlock);

    /* Compute the initial keystream block. */
    cipher->primitive->fForward(cipher, cfb(mode->ctx)->iv, cipher->primitive->szBlock);
    cfb(mode->ctx)->remaining = cipher->primitive->szBlock;

    /* Return success. */
    return ORDO_ESUCCESS;
}

void CFB_EncryptUpdate(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
    /* Variable to store how much data can be processed per iteration. */
    size_t process = 0;

    /* Initialize the output size. */
    *outlen = 0;

    /* Go over the buffer byte per byte. */
    while (inlen != 0)
    {
        /* If there is no data left in the context block, update. */
        if (cfb(mode->ctx)->remaining == 0)
        {
            /* CFB update (simply apply the permutation function again). */
            cipher->primitive->fForward(cipher, cfb(mode->ctx)->iv, cipher->primitive->szBlock);
            cfb(mode->ctx)->remaining = cipher->primitive->szBlock;
        }

        /* Compute the amount of data to process. */
        process = (inlen < cfb(mode->ctx)->remaining) ? inlen : cfb(mode->ctx)->remaining;

        /* Process this amount of data. */
        memmove(out, in, process);
        xorBuffer(out, (unsigned char*)cfb(mode->ctx)->iv + cipher->primitive->szBlock - cfb(mode->ctx)->remaining, process);
        memcpy((unsigned char*)cfb(mode->ctx)->iv + cipher->primitive->szBlock - cfb(mode->ctx)->remaining, out, process);
        cfb(mode->ctx)->remaining -= process;
        (*outlen) += process;
        inlen -= process;
        out += process;
        in += process;
    }
}

void CFB_DecryptUpdate(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
    /* Variable to store how much data can be processed per iteration. */
    size_t process = 0;

    /* Initialize the output size. */
    *outlen = 0;

    /* Go over the buffer byte per byte. */
    while (inlen != 0)
    {
        /* If there is no data left in the context block, update. */
        if (cfb(mode->ctx)->remaining == 0)
        {
            /* CFB update (simply apply the permutation function again). */
            cipher->primitive->fForward(cipher, cfb(mode->ctx)->iv, cipher->primitive->szBlock);
            cfb(mode->ctx)->remaining = cipher->primitive->szBlock;
        }

        /* Compute the amount of data to process. */
        process = (inlen < cfb(mode->ctx)->remaining) ? inlen : cfb(mode->ctx)->remaining;

        /* Process this amount of data. */
        memmove(out, in, process);
        xorBuffer(out, (unsigned char*)cfb(mode->ctx)->iv + cipher->primitive->szBlock - cfb(mode->ctx)->remaining, process);
        memcpy((unsigned char*)cfb(mode->ctx)->iv + cipher->primitive->szBlock - cfb(mode->ctx)->remaining, in, process);
        cfb(mode->ctx)->remaining -= process;
        (*outlen) += process;
        inlen -= process;
        out += process;
        in += process;
    }
}

int CFB_Final(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* out, size_t* outlen)
{
    /* Write output size if applicable. */
    if (outlen != 0) *outlen = 0;

    /* Return success. */
    return ORDO_ESUCCESS;
}

void CFB_Free(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher)
{
    /* Free context space. */
    sfree(cfb(mode->ctx)->iv, cipher->primitive->szBlock);
    sfree(mode->ctx, sizeof(CFB_ENCRYPT_CONTEXT));
    sfree(mode, sizeof(ENCRYPT_MODE_CONTEXT));
}

/* Fills a ENCRYPT_MODE struct with the correct information. */
void CFB_SetMode(ENCRYPT_MODE* mode)
{
    ENCRYPT_MAKEMODE(mode, CFB_Create, CFB_Init, CFB_EncryptUpdate, CFB_DecryptUpdate, CFB_Final, CFB_Final, CFB_Free, "CFB");
}
