#include <primitives/primitives.h>
#include <encrypt/encrypt.h>
#include <encrypt/modes/stream.h>

/* Shorthand macro for context casting. */
#define stream(ctx) ((STREAM_ENCRYPT_CONTEXT*)ctx)

void STREAM_Create(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher)
{
    /* This mode of operation maintains no state. */
}

int STREAM_Init(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, void* iv, void* params)
{
    /* Return success. */
    return ORDO_ESUCCESS;
}

void STREAM_Update(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
    /* Copy the plaintext to the ciphertext buffer. */
    memmove(out, in, inlen);

    /* Simply generate a keystream of the right length and exclusive-or it with the plaintext. */
    cipher->primitive->fForward(cipher, out, inlen);

    /* Set the output length. */
    *outlen = inlen;
}

int STREAM_Final(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* out, size_t* outlen)
{
    /* Write output size if applicable. */
    if (outlen != 0) *outlen = 0;

    /* Return success. */
    return ORDO_ESUCCESS;
}

void STREAM_Free(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher)
{
    /* Nothing to free... */
}

/* Fills a ENCRYPT_MODE struct with the correct information. */
void STREAM_SetMode(ENCRYPT_MODE* mode)
{
    ENCRYPT_MAKEMODE(mode, STREAM_Create, STREAM_Init, STREAM_Update, STREAM_Update, STREAM_Final, STREAM_Final, STREAM_Free, "STREAM");
}
