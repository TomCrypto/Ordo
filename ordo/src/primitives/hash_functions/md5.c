#include <primitives/hash_functions/md5.h>

/* The Md5 digest size. */
#define MD5_DIGEST (16)
/* The MD5 block size. */
#define MD5_BLOCK (64)

/* The MD5 initial state vector. */
const uint32_t MD5_initialState[4] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};

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
    /* Allocate memory for the MD5 state. */
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
inline void MD5_Compress(uint32_t block[16], uint32_t digest[4])
{
    /* Temporary variables. */
    uint32_t a, b, c, d;

    /* Save the current state. */
    a = digest[0];
    b = digest[1];
    c = digest[2];
    d = digest[3];

    a += block[ 0] + 0xD76AA478 + (d ^ (b & (c ^ d)));
    a = ((a <<  7) | (a >> 25)) + b;
    d += block[ 1] + 0xE8C7B756 + (c ^ (a & (b ^ c)));
    d = ((d << 12) | (d >> 20)) + a;
    c += block[ 2] + 0x242070DB + (b ^ (d & (a ^ b)));
    c = ((c << 17) | (c >> 15)) + d;
    b += block[ 3] + 0xC1BDCEEE + (a ^ (c & (d ^ a)));
    b = ((b << 22) | (b >> 10)) + c;
    a += block[ 4] + 0xF57C0FAF + (d ^ (b & (c ^ d)));
    a = ((a <<  7) | (a >> 25)) + b;
    d += block[ 5] + 0x4787C62A + (c ^ (a & (b ^ c)));
    d = ((d << 12) | (d >> 20)) + a;
    c += block[ 6] + 0xA8304613 + (b ^ (d & (a ^ b)));
    c = ((c << 17) | (c >> 15)) + d;
    b += block[ 7] + 0xFD469501 + (a ^ (c & (d ^ a)));
    b = ((b << 22) | (b >> 10)) + c;
    a += block[ 8] + 0x698098D8 + (d ^ (b & (c ^ d)));
    a = ((a <<  7) | (a >> 25)) + b;
    d += block[ 9] + 0x8B44F7AF + (c ^ (a & (b ^ c)));
    d = ((d << 12) | (d >> 20)) + a;
    c += block[10] + 0xFFFF5BB1 + (b ^ (d & (a ^ b)));
    c = ((c << 17) | (c >> 15)) + d;
    b += block[11] + 0x895CD7BE + (a ^ (c & (d ^ a)));
    b = ((b << 22) | (b >> 10)) + c;
    a += block[12] + 0x6B901122 + (d ^ (b & (c ^ d)));
    a = ((a <<  7) | (a >> 25)) + b;
    d += block[13] + 0xFD987193 + (c ^ (a & (b ^ c)));
    d = ((d << 12) | (d >> 20)) + a;
    c += block[14] + 0xA679438E + (b ^ (d & (a ^ b)));
    c = ((c << 17) | (c >> 15)) + d;
    b += block[15] + 0x49B40821 + (a ^ (c & (d ^ a)));
    b = ((b << 22) | (b >> 10)) + c;

    a += block[ 1] + 0xF61E2562 + (c ^ (d & (b ^ c)));
    a = ((a <<  5) | (a >> 27)) + b;
    d += block[ 6] + 0xC040B340 + (b ^ (c & (a ^ b)));
    d = ((d <<  9) | (d >> 23)) + a;
    c += block[11] + 0x265E5A51 + (a ^ (b & (d ^ a)));
    c = ((c << 14) | (c >> 18)) + d;
    b += block[ 0] + 0xE9B6C7AA + (d ^ (a & (c ^ d)));
    b = ((b << 20) | (b >> 12)) + c;
    a += block[ 5] + 0xD62F105D + (c ^ (d & (b ^ c)));
    a = ((a <<  5) | (a >> 27)) + b;
    d += block[10] + 0x02441453 + (b ^ (c & (a ^ b)));
    d = ((d <<  9) | (d >> 23)) + a;
    c += block[15] + 0xD8A1E681 + (a ^ (b & (d ^ a)));
    c = ((c << 14) | (c >> 18)) + d;
    b += block[ 4] + 0xE7D3FBC8 + (d ^ (a & (c ^ d)));
    b = ((b << 20) | (b >> 12)) + c;
    a += block[ 9] + 0x21E1CDE6 + (c ^ (d & (b ^ c)));
    a = ((a <<  5) | (a >> 27)) + b;
    d += block[14] + 0xC33707D6 + (b ^ (c & (a ^ b)));
    d = ((d <<  9) | (d >> 23)) + a;
    c += block[ 3] + 0xF4D50D87 + (a ^ (b & (d ^ a)));
    c = ((c << 14) | (c >> 18)) + d;
    b += block[ 8] + 0x455A14ED + (d ^ (a & (c ^ d)));
    b = ((b << 20) | (b >> 12)) + c;
    a += block[13] + 0xA9E3E905 + (c ^ (d & (b ^ c)));
    a = ((a <<  5) | (a >> 27)) + b;
    d += block[ 2] + 0xFCEFA3F8 + (b ^ (c & (a ^ b)));
    d = ((d <<  9) | (d >> 23)) + a;
    c += block[ 7] + 0x676F02D9 + (a ^ (b & (d ^ a)));
    c = ((c << 14) | (c >> 18)) + d;
    b += block[12] + 0x8D2A4C8A + (d ^ (a & (c ^ d)));
    b = ((b << 20) | (b >> 12)) + c;

    a += block[ 5] + 0xFFFA3942 + (b ^ c ^ d);
    a = ((a << 4)  | (a >> 28)) + b;
    d += block[ 8] + 0x8771F681 + (a ^ b ^ c);
    d = ((d << 11) | (d >> 21)) + a;
    c += block[11] + 0x6D9D6122 + (d ^ a ^ b);
    c = ((c << 16) | (c >> 16)) + d;
    b += block[14] + 0xFDE5380C + (c ^ d ^ a);
    b = ((b << 23) | (b >> 9))  + c;
    a += block[ 1] + 0xA4BEEA44 + (b ^ c ^ d);
    a = ((a << 4)  | (a >> 28)) + b;
    d += block[ 4] + 0x4BDECFA9 + (a ^ b ^ c);
    d = ((d << 11) | (d >> 21)) + a;
    c += block[ 7] + 0xF6BB4B60 + (d ^ a ^ b);
    c = ((c << 16) | (c >> 16)) + d;
    b += block[10] + 0xBEBFBC70 + (c ^ d ^ a);
    b = ((b << 23) | (b >>  9)) + c;
    a += block[13] + 0x289B7EC6 + (b ^ c ^ d);
    a = ((a <<  4) | (a >> 28)) + b;
    d += block[ 0] + 0xEAA127FA + (a ^ b ^ c);
    d = ((d << 11) | (d >> 21)) + a;
    c += block[ 3] + 0xD4EF3085 + (d ^ a ^ b);
    c = ((c << 16) | (c >> 16)) + d;
    b += block[ 6] + 0x04881D05 + (c ^ d ^ a);
    b = ((b << 23) | (b >>  9)) + c;
    a += block[ 9] + 0xD9D4D039 + (b ^ c ^ d);
    a = ((a <<  4) | (a >> 28)) + b;
    d += block[12] + 0xE6DB99E5 + (a ^ b ^ c);
    d = ((d << 11) | (d >> 21)) + a;
    c += block[15] + 0x1FA27CF8 + (d ^ a ^ b);
    c = ((c << 16) | (c >> 16)) + d;
    b += block[ 2] + 0xC4AC5665 + (c ^ d ^ a);
    b = ((b << 23) | (b >>  9)) + c;

    a += block[ 0] + 0xF4292244 + (c ^ (b | (~d)));
    a = ((a <<  6) | (a >> 26)) + b;
    d += block[ 7] + 0x432AFF97 + (b ^ (a | (~c)));
    d = ((d << 10) | (d >> 22)) + a;
    c += block[14] + 0xAB9423A7 + (a ^ (d | (~b)));
    c = ((c << 15) | (c >> 17)) + d;
    b += block[ 5] + 0xFC93A039 + (d ^ (c | (~a)));
    b = ((b << 21) | (b >> 11)) + c;
    a += block[12] + 0x655B59C3 + (c ^ (b | (~d)));
    a = ((a <<  6) | (a >> 26)) + b;
    d += block[ 3] + 0x8F0CCC92 + (b ^ (a | (~c)));
    d = ((d << 10) | (d >> 22)) + a;
    c += block[10] + 0xFFEFF47D + (a ^ (d | (~b)));
    c = ((c << 15) | (c >> 17)) + d;
    b += block[ 1] + 0x85845DD1 + (d ^ (c | (~a)));
    b = ((b << 21) | (b >> 11)) + c;
    a += block[ 8] + 0x6FA87E4F + (c ^ (b | (~d)));
    a = ((a <<  6) | (a >> 26)) + b;
    d += block[15] + 0xFE2CE6E0 + (b ^ (a | (~c)));
    d = ((d << 10) | (d >> 22)) + a;
    c += block[ 6] + 0xA3014314 + (a ^ (d | (~b)));
    c = ((c << 15) | (c >> 17)) + d;
    b += block[13] + 0x4E0811A1 + (d ^ (c | (~a)));
    b = ((b << 21) | (b >> 11)) + c;
    a += block[ 4] + 0xF7537E82 + (c ^ (b | (~d)));
    a = ((a <<  6) | (a >> 26)) + b;
    d += block[11] + 0xBD3AF235 + (b ^ (a | (~c)));
    d = ((d << 10) | (d >> 22)) + a;
    c += block[ 2] + 0x2AD7D2BB + (a ^ (d | (~b)));
    c = ((c << 15) | (c >> 17)) + d;
    b += block[ 9] + 0xEB86D391 + (d ^ (c | (~a)));
    b = ((b << 21) | (b >> 11)) + c;

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
    MAKE_HASH_FUNCTION(hash, MD5_DIGEST, MD5_BLOCK, MD5_Create, MD5_Init, MD5_Update, MD5_Final, MD5_Free, "MD5");
}
