#include <primitives/primitives.h>
#include <encrypt/encrypt.h>
#include <encrypt/modes/ofb.h>

/* This is extra context space required by the OFB mode to store the amount of state not used.*/
typedef struct OFB_ENCRYPT_CONTEXT
{
    /* A buffer for the IV. */
    void* iv;
    /* The amount of bytes of unused state remaining before the state is to be renewed. */
    size_t remaining;
} OFB_ENCRYPT_CONTEXT;

/* Shorthand macro for context casting. */
#define ofb(ctx) ((OFB_ENCRYPT_CONTEXT*)ctx)

void OFB_Create(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher)
{
    /* Allocate context space. */
    mode->ctx = salloc(sizeof(OFB_ENCRYPT_CONTEXT));
    ofb(mode->ctx)->iv = salloc(cipher->primitive->szBlock);
    ofb(mode->ctx)->remaining = 0;
}

int OFB_Init(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, void* iv, void* params)
{
    /* Copy the IV (required) into the context IV. */
    memcpy(ofb(mode->ctx)->iv, iv, cipher->primitive->szBlock);

    /* Compute the initial keystream block. */
    cipher->primitive->fForward(cipher, ofb(mode->ctx)->iv, cipher->primitive->szBlock);
    ofb(mode->ctx)->remaining = cipher->primitive->szBlock;

    /* Return success. */
    return ORDO_ESUCCESS;
}

void OFB_Update(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
    /* Variable to store how much data can be processed per iteration. */
    size_t process = 0;

    /* Initialize the output size. */
    *outlen = 0;

    /* Go over the buffer byte per byte. */
    while (inlen != 0)
    {
        /* If there is no data left in the context block, update. */
        if (ofb(mode->ctx)->remaining == 0)
        {
            /* OFB update (simply apply the permutation function again). */
            cipher->primitive->fForward(cipher, ofb(mode->ctx)->iv, cipher->primitive->szBlock);
            ofb(mode->ctx)->remaining = cipher->primitive->szBlock;
        }

        /* Compute the amount of data to process. */
        process = (inlen < ofb(mode->ctx)->remaining) ? inlen : ofb(mode->ctx)->remaining;

        /* Process this amount of data. */
        memmove(out, in, process);
        xorBuffer(out, (unsigned char*)ofb(mode->ctx)->iv + cipher->primitive->szBlock - ofb(mode->ctx)->remaining, process);
        ofb(mode->ctx)->remaining -= process;
        (*outlen) += process;
        inlen -= process;
        out += process;
        in += process;
    }
}

int OFB_Final(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* out, size_t* outlen)
{
    /* Write output size if applicable. */
    if (outlen != 0) *outlen = 0;

    /* Return success. */
    return ORDO_ESUCCESS;
}

void OFB_Free(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher)
{
    /* Free context space. */
    sfree(ofb(mode->ctx)->iv, cipher->primitive->szBlock);
    sfree(mode->ctx, sizeof(OFB_ENCRYPT_CONTEXT));
}

/* Fills a ENCRYPT_MODE struct with the correct information. */
void OFB_SetMode(ENCRYPT_MODE* mode)
{
    ENCRYPT_MAKEMODE(mode, OFB_Create, OFB_Init, OFB_Update, OFB_Update, OFB_Final, OFB_Final, OFB_Free, "OFB");
}
