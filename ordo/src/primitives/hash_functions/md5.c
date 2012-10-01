#include <primitives/hash_functions/md5.h>

/* The Md5 digest size. */
#define MD5_DIGEST (16)
/* The MD5 block size. */
#define MD5_BLOCK (64)

/* The MD5 initial state vector. */
const uint32_t MD5_initialState[4] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};

/* The MD5 constant table. */
const uint32_t MD5_constants[64] = {0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
                                    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
                                    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
                                    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
                                    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
                                    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
                                    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
                                    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
                                    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
                                    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
                                    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
                                    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
                                    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
                                    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
                                    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
                                    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

/* The MD5 rotation constants. */
const uint32_t MD5_rotation[64] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                                   5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
                                   4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                                   6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

/* 32-bit left and right rotation. */
#define ROL(n, r) (((n) << (r)) | ((n) >> (32 - (r))))
#define ROR(n, r) (((n) >> (r)) | ((n) << (32 - (r))))

/* A MD5 state. */
typedef struct MD5_STATE
{
    uint32_t digest[4];
    uint32_t block[16];
    uint64_t blockLength;
    uint64_t messageLength;
} MD5_STATE;

/* Shorthand macro for context casting. */
#define state(x) ((MD5_STATE*)(x->ctx))

HASH_FUNCTION_CONTEXT* MD5_Create()
{
    /* Allocate memory for the SHA-256 state. */
    HASH_FUNCTION_CONTEXT* ctx = salloc(sizeof(HASH_FUNCTION_CONTEXT));
    if (ctx)
    {
        if ((ctx->ctx = salloc(sizeof(MD5_STATE)))) return ctx;
        sfree(ctx, sizeof(HASH_FUNCTION_CONTEXT));
    }

    /* Allocation failed. */
    return 0;
}

int MD5_Init(HASH_FUNCTION_CONTEXT* ctx, void* params)
{
    /* Set the digest to the initial state. */
    memcpy(state(ctx)->digest, MD5_initialState, MD5_DIGEST);
    state(ctx)->messageLength = 0;
    state(ctx)->blockLength = 0;

    /* Ignore the parameters, since MD5 has none. */
    return ORDO_ESUCCESS;
}

/* This is the MD5 compression function. */
inline void MD5_Compress(uint32_t block[16], uint32_t digest[8])
{
    /* Temporary variables. */
    uint32_t a, b, c, d, f, u, x;
    size_t t;

    /* Save the current state. */
    a = digest[0];
    b = digest[1];
    c = digest[2];
    d = digest[3];

    /* Perform 64 MD5 rounds. */
    for (t = 0; t < 16; t++)
    {
        f = (b & c) | ((~b) & d);
        u = b + ROL(a + f + MD5_constants[t] + block[(1 * t + 0) % 16], MD5_rotation[t]);

        x = d;
        d = c;
        c = b;
        b = u;
        a = x;
    }

    for (t = 16; t < 32; t++)
    {
        f = (d & b) | ((~d) & c);
        u = b + ROL(a + f + MD5_constants[t] + block[(5 * t + 1) % 16], MD5_rotation[t]);

        x = d;
        d = c;
        c = b;
        b = u;
        a = x;
    }

    for (t = 32; t < 48; t++)
    {
        f = b ^ c ^ d;
        u = b + ROL(a + f + MD5_constants[t] + block[(3 * t + 5) % 16], MD5_rotation[t]);

        x = d;
        d = c;
        c = b;
        b = u;
        a = x;
    }

    for (t = 48; t < 64; t++)
    {
        f = c ^ (b | (~d));
        u = b + ROL(a + f + MD5_constants[t] + block[(7 * t + 0) % 16], MD5_rotation[t]);

        x = d;
        d = c;
        c = b;
        b = u;
        a = x;
    }

    /* Feed-forward the hash state. */
    digest[0] += a;
    digest[1] += b;
    digest[2] += c;
    digest[3] += d;
}

void MD5_Update(HASH_FUNCTION_CONTEXT* ctx, void* buffer, size_t size)
{
    /* Some variables. */
    size_t pad = 0;

    /* Increment the message length. */
    state(ctx)->messageLength += size;

    /* Is the message provided long enough to complete a block? */
    if (state(ctx)->blockLength + size >= MD5_BLOCK)
    {
        /* Compute how much of the message is needed to complete the block. */
        pad = MD5_BLOCK - state(ctx)->blockLength;
        memcpy(((unsigned char*)state(ctx)->block) + state(ctx)->blockLength, buffer, pad);

        /* We now have a complete block which we can process. */
        MD5_Compress(state(ctx)->block, state(ctx)->digest);
        state(ctx)->blockLength = 0;

        /* Offset the message accordingly. */
        buffer = (unsigned char*)buffer + pad;
        size -= pad;

        /* At this point, the block is empty, so process complete blocks directly. */
        while (size >= MD5_BLOCK)
        {
            /* Just process this block. */
            memcpy(state(ctx)->block, buffer, MD5_BLOCK);
            MD5_Compress(state(ctx)->block, state(ctx)->digest);
            buffer = (unsigned char*)buffer + MD5_BLOCK;
            size -= MD5_BLOCK;
        }
    }

    /* If we have anything left over, just append it to the context's block field. */
    memcpy(((unsigned char*)state(ctx)->block) + state(ctx)->blockLength, buffer, size);
    state(ctx)->blockLength += size;
}

void MD5_Final(HASH_FUNCTION_CONTEXT* ctx, void* digest)
{
    /* Some variables. */
    uint8_t byte = 0x80;
    size_t zeroBytes;
    uint64_t len;

    /* Save the message's length (in bits) before final processing (little-endian for MD5). */
    len = htole64(state(ctx)->messageLength * 8);

    /* Append a '1' bit to the message. */
    MD5_Update(ctx, &byte, sizeof(byte));

    /* Calculate the number of '0' bits to append. */
    zeroBytes = (MD5_BLOCK - sizeof(uint64_t) - state(ctx)->blockLength) % MD5_BLOCK;

    /* Append that many '0' bits. */
    byte = 0x00;
    while (zeroBytes--) MD5_Update(ctx, &byte, sizeof(byte));

    /* Append the message length (on 64 bits). */
    MD5_Update(ctx, &len, sizeof(len));

    /* Copy the final digest. */
    memcpy(digest, state(ctx)->digest, MD5_DIGEST);
}

void MD5_Free(HASH_FUNCTION_CONTEXT* ctx)
{
    /* Free memory for the MD5 state. */
    sfree(ctx->ctx, sizeof(MD5_STATE));
    sfree(ctx, sizeof(HASH_FUNCTION_CONTEXT));
}

/* Fills a HASH_FUNCTION struct with the correct information. */
void MD5_SetPrimitive(HASH_FUNCTION* hash)
{
    MAKE_HASH_FUNCTION(hash, MD5_DIGEST, MD5_Create, MD5_Init, MD5_Update, MD5_Final, MD5_Free, "MD5");
}
