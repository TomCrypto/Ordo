#include <ordo.h>

#include <common/ordo_errors.h>

/******************************************************************************/

/* Load Ordo. */
void load_ordo()
{
    /* Load all cryptographic primitives. */
    load_primitives();

    /* Load all encryption modes of operation. */
    load_block_modes();
}

/* This convenience function encrypts a buffer with a given block cipher, key, IV, and parameters. */
int ordoEncrypt(void* in, size_t inlen, void* out, size_t* outlen, const struct BLOCK_CIPHER* primitive, const struct BLOCK_MODE* mode, void* key, size_t keySize, void* iv, size_t iv_len, void* cipherParams, void* modeParams)
{
    int error;
    size_t outPos = 0;

    /* Create the context. */
    struct ENC_BLOCK_CTX* ctx = enc_block_alloc(primitive, mode);
    if (!ctx) return ORDO_ALLOC;

    /* Initialize it. */
    error = enc_block_init(ctx, key, keySize, iv, iv_len, 1, cipherParams, modeParams);
    if (error == ORDO_SUCCESS)
    {
        /* Encrypt the buffer. */
        enc_block_update(ctx, in, inlen, out, outlen);
        outPos += *outlen;

        /* Finalize the context. */
        error = enc_block_final(ctx, (unsigned char*)out + outPos, outlen);
        if (error == ORDO_SUCCESS) *outlen += outPos;
    }

    /* Free the context and return success or failure. */
    enc_block_free(ctx);
    return error;
}

/* This convenience function decrypts a buffer with a given block cipher, key, IV, and parameters. */
int ordoDecrypt(void* in, size_t inlen, void* out, size_t* outlen, const struct BLOCK_CIPHER* primitive, const struct BLOCK_MODE* mode, void* key, size_t keySize, void* iv, size_t iv_len, void* cipherParams, void* modeParams)
{
    int error;
    size_t outPos = 0;

    /* Create the context. */
    struct ENC_BLOCK_CTX* ctx = enc_block_alloc(primitive, mode);
    if (!ctx) return ORDO_ALLOC;

    /* Initialize it. */
    error = enc_block_init(ctx, key, keySize, iv, iv_len, 0, cipherParams, modeParams);
    if (error == ORDO_SUCCESS)
    {
        /* Encrypt the buffer. */
        enc_block_update(ctx, in, inlen, out, outlen);
        outPos += *outlen;

        /* Finalize the context. */
        error = enc_block_final(ctx, (unsigned char*)out + outPos, outlen);
        if (error == ORDO_SUCCESS) *outlen += outPos;
    }

    /* Free the context and return success or failure. */
    enc_block_free(ctx);
    return error;
}

/* This convenience function encrypts or decrypts a buffer with a given stream cipher, key, IV, and parameters. */
int ordoEncryptStream(void* inout, size_t len, const struct STREAM_CIPHER* primitive, void* key, size_t keySize, void* cipherParams)
{
    int error;

    /* Create the context. */
    struct ENC_STREAM_CTX* ctx = enc_stream_alloc(primitive);
    if (!ctx) return ORDO_ALLOC;

    /* Initialize it and encrypt the buffer. */
    error = enc_stream_init(ctx, key, keySize, cipherParams);
    if (error == ORDO_SUCCESS) enc_stream_update(ctx, inout, len);

    /* Free the context and return success or failure. */
    enc_stream_free(ctx);
    return error;
}

/* Hashes a message. */
int ordoHash(void* in, size_t len, void* out, const struct HASH_FUNCTION* hash, void* hashParams)
{
    int error;

    /* Create the context. */
    struct DIGEST_CTX* ctx = digest_alloc(hash);
    if (!ctx) return ORDO_ALLOC;

    /* Initialize it. */
    error = digest_init(ctx, hashParams);
    if (error == ORDO_SUCCESS)
    {
        /* Hash the buffer. */
        digest_update(ctx, in, len);

        /* Finalize the context. */
        digest_final(ctx, out);
    }

    /* Free the context and return success or failure. */
    digest_free(ctx);
    return error;
}

/* HMAC. */
int ordoHMAC(void* in, size_t len, void* key, size_t keySize, void* out, const struct HASH_FUNCTION* hash, void* hashParams)
{
    int error;

    /* Create the context. */
    struct HMAC_CTX* ctx = hmac_alloc(hash);
    if (!ctx) return ORDO_ALLOC;

    /* Initialize it. */
    error = hmac_init(ctx, key, keySize, hashParams);
    if (error == ORDO_SUCCESS)
    {
        /* Hash the buffer. */
        hmac_update(ctx, in, len);

        /* Finalize the context. */
        error = hmac_final(ctx, out);
    }

    /* Free the context and return success or failure. */
    hmac_free(ctx);
    return error;
}
