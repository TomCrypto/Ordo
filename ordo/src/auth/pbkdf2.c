#include <auth/pbkdf2.h>
#include <ordo.h>

int pbkdf2(HASH_FUNCTION* hash, void *password, size_t passwordLen, void *salt,
           size_t saltLen, size_t iterations, size_t outputLen, void *digest,
           void *hashParams)
{
    int err = ORDO_ESUCCESS;

    /* We first start by allocating as much memory as the output length rounded
     * up to the nearest block size of the underlying hash function. */
    size_t digestLen = hashFunctionDigestSize(hash);
    size_t bufLen = outputLen - outputLen % digestLen + digestLen;
    size_t t, i;

    HMAC_CONTEXT *ctx = hmacCreate(hash);
    HMAC_CONTEXT *ini = hmacCreate(hash);

    void *buf = malloc(bufLen);
    void *tmp = salloc(digestLen);
    void *initial = salloc(digestLen);
    void *in = salloc(saltLen + sizeof(uint32_t)); /* Salt + Counter */

    if ((outputLen == 0) || (iterations == 0))
    {
        err = ORDO_EPARAM;
        goto pbkdf2_f;
    }

    if ((ctx == 0) || (ini == 0) || (buf == 0) || (tmp == 0) || (initial == 0) || (in == 0))
    {
        err = ORDO_EHEAPALLOC;
        goto pbkdf2_f;
    }

    memcpy(in, salt, saltLen);

    /* Now we iterate the PBKDF2 round function on as many blocks as needed.
     * For some reason the counter starts at 1. */
    for (t = 1; t < bufLen / digestLen + 1; ++t)
    {
        void *bufPtr = (unsigned char*)buf + (t - 1) * digestLen;

        uint32_t counter = htobe32(t); /* Big-endian counter. */
        memcpy((unsigned char*)in + saltLen, &counter, sizeof(uint32_t));
        err = ordoHMAC(in, saltLen + sizeof(uint32_t), password, passwordLen,
                      initial, hash, hashParams);
        if (err != ORDO_ESUCCESS) goto pbkdf2_f;
        memcpy(bufPtr, initial, digestLen);

        err = hmacInit(ini, password, passwordLen, hashParams);
        if (err != ORDO_ESUCCESS) goto pbkdf2_f;

        /* Now chain over the desired number of iterations, xor together. */
        for (i = 1; i < iterations; ++i)
        {
            memcpy(tmp, initial, digestLen);

            /* Doing some state copying here since the inner HMAC doesn't
             * actually change across iterations, so we may as well reuse
             * it and save a lot of time. */
            hmacCopy(ctx, ini);
            hmacUpdate(ctx, tmp, digestLen);
            err = hmacFinal(ctx, initial);
            if (err != ORDO_ESUCCESS) goto pbkdf2_f;

            xorBuffer(bufPtr, initial, digestLen);
        }
    }

pbkdf2_f:
    /* Copy the first outputLen bytes to the output. */
    if (buf) memcpy(digest, buf, outputLen);

    sfree(in, saltLen + sizeof(uint32_t));
    sfree(initial, digestLen);
    sfree(tmp, digestLen);
    free(buf);

    if (ctx) hmacFree(ctx);
    if (ini) hmacFree(ini);

    return err;
}
