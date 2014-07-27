/*===-- sha1.c ----------------------------------------*- generic -*- C -*-===*/

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

#include "ordo/primitives/hash_functions/sha1.h"

/*===----------------------------------------------------------------------===*/

#define SHA1_DIGEST (bits(160))
#define SHA1_BLOCK  (bits(512))

static void sha1_compress(const uint32_t * RESTRICT block,
                          uint32_t * RESTRICT digest) HOT_CODE;

static const uint32_t sha1_iv[5] =
{
    0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0
};

#ifdef OPAQUE
struct SHA1_STATE
{
    uint32_t digest[5];
    uint32_t block[16];
    uint64_t block_len;
    uint64_t msg_len;
};
#endif

/*===----------------------------------------------------------------------===*/

int sha1_init(struct SHA1_STATE *state,
              const void *params)
{
    state->digest[0] = sha1_iv[0];
    state->digest[1] = sha1_iv[1];
    state->digest[2] = sha1_iv[2];
    state->digest[3] = sha1_iv[3];
    state->digest[4] = sha1_iv[4];
    state->block_len = 0;
    state->msg_len = 0;

    return ORDO_SUCCESS;
}

void sha1_update(struct SHA1_STATE *state,
                 const void *buffer, size_t len)
{
    if (!len) return;

    state->msg_len += len;

    if (state->block_len + len >= SHA1_BLOCK)
    {
        size_t pad = (size_t)(SHA1_BLOCK - state->block_len);

        memcpy(offset(state->block, state->block_len), buffer, pad);
        sha1_compress(state->block, state->digest);
        state->block_len = 0;

        buffer = offset(buffer, pad);
        len -= pad;

        while (len >= SHA1_BLOCK)
        {
            memcpy(state->block, buffer, SHA1_BLOCK);
            sha1_compress(state->block, state->digest);

            buffer = offset(buffer, SHA1_BLOCK);
            len -= SHA1_BLOCK;
        }
    }

    memcpy(offset(state->block, state->block_len), buffer, len);
    state->block_len += len;
}

void sha1_final(struct SHA1_STATE *state,
                void *digest)
{
    /* See the MD5 code for a description of Merkle padding. */

    unsigned char padding[SHA1_BLOCK] = { 0x80 };
    uint64_t len = tobe64(bytes(state->msg_len));
    size_t block_len = (size_t)state->block_len;

    size_t pad_len = SHA1_BLOCK - block_len - sizeof(uint64_t)
                   + (block_len < SHA1_BLOCK - sizeof(uint64_t)
                     ? 0 : SHA1_BLOCK);

    sha1_update(state, padding, pad_len);
    sha1_update(state, &len, sizeof(len));

    state->digest[0] = tobe32(state->digest[0]);
    state->digest[1] = tobe32(state->digest[1]);
    state->digest[2] = tobe32(state->digest[2]);
    state->digest[3] = tobe32(state->digest[3]);
    state->digest[4] = tobe32(state->digest[4]);

    memcpy(digest, state->digest, SHA1_DIGEST);
}

/*===----------------------------------------------------------------------===*/

#define F1(x, y, z) ((x & y) | ((~x) & z))
#define F2(x, y, z) (x ^ y ^ z)
#define F3(x, y, z) ((x & y) | (x & z) | (y & z))
#define F4(x, y, z) F2(x, y, z)

void sha1_compress(const uint32_t * RESTRICT block,
                   uint32_t * RESTRICT digest)
{
    size_t t;

    uint32_t a = digest[0];
    uint32_t b = digest[1];
    uint32_t c = digest[2];
    uint32_t d = digest[3];
    uint32_t e = digest[4];

    uint32_t w[80];

    for (t = 0; t < 16; ++t)
        w[t] = tobe32(block[t]);

    for (t = 16; t < 80; ++t)
        w[t] = rol32(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1);

    for (t = 0; t < 20; ++t)
    {
        uint32_t m = rol32(a, 5) + F1(b, c, d) + e + w[t] + 0x5a827999;
        e = d; d = c; c = rol32(b, 30); b = a; a = m;
    }

    for (t = 20; t < 40; ++t)
    {
        uint32_t m = rol32(a, 5) + F2(b, c, d) + e + w[t] + 0x6ed9eba1;
        e = d; d = c; c = rol32(b, 30); b = a; a = m;
    }

    for (t = 40; t < 60; ++t)
    {
        uint32_t m = rol32(a, 5) + F3(b, c, d) + e + w[t] + 0x8f1bbcdc;
        e = d; d = c; c = rol32(b, 30); b = a; a = m;
    }

    for (t = 60; t < 80; ++t)
    {
        uint32_t m = rol32(a, 5) + F4(b, c, d) + e + w[t] + 0xca62c1d6;
        e = d; d = c; c = rol32(b, 30); b = a; a = m;
    }

    digest[0] += a;
    digest[1] += b;
    digest[2] += c;
    digest[3] += d;
    digest[4] += e;
}
