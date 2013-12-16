#include "ordo/primitives/hash_functions/sha256.h"

#include "ordo/internal/environment.h"
#include "ordo/internal/endianness.h"

#include "ordo/internal/mem.h"
#include "ordo/common/utils.h"

#include <string.h>

/******************************************************************************/

#define SHA256_DIGEST (bits(256))
#define SHA256_BLOCK  (bits(512))

static const uint32_t sha256_iv[8] =
{
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

static const uint32_t sha256_table[64] =
{
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define ma(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define ch(x, y, z) ((x & y) ^ (~x & z))

static void ORDO_CALLCONV
sha256_compress(const uint32_t block[16], uint32_t digest[8])
ORDO_HOT_CODE;

void ORDO_CALLCONV
sha256_compress(const uint32_t block[16], uint32_t digest[8])
{
    size_t t;

    uint32_t a = digest[0];
    uint32_t b = digest[1];
    uint32_t c = digest[2];
    uint32_t d = digest[3];
    uint32_t e = digest[4];
    uint32_t f = digest[5];
    uint32_t g = digest[6];
    uint32_t h = digest[7];

    uint32_t w[64]; /* The "message schedule" array. */

    for (t = 0; t < 16; ++t) w[t] = htobe32(block[t]);

    for (t = 16; t < 64; ++t)
    {
        uint32_t r1 = ror32(w[t -  2], 17) ^ ror32(w[t -  2], 19);
        uint32_t r2 = ror32(w[t - 15],  7) ^ ror32(w[t - 15], 18);

        r1 ^= w[t -  2] >> 10;
        r2 ^= w[t - 15] >>  3;

        w[t] = w[t - 16] + w[t - 7] + r1 + r2;
    }
                
    for (t = 0; t < 64; ++t)
    {
        uint32_t t2 = (ror32(a, 2) ^ ror32(a, 13) ^ ror32(a, 22));
        uint32_t t1 = (ror32(e, 6) ^ ror32(e, 11) ^ ror32(e, 25));

        t1 += ch(e, f, g) + h + w[t] + sha256_table[t];
        t2 += ma(a, b, c);

        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    digest[0] += a;
    digest[1] += b;
    digest[2] += c;
    digest[3] += d;
    digest[4] += e;
    digest[5] += f;
    digest[6] += g;
    digest[7] += h;
}

/******************************************************************************/

struct SHA256_STATE
{
    uint32_t digest[8];
    uint32_t block[16];
    uint64_t block_len;
    uint64_t msg_len;
};

struct SHA256_STATE * ORDO_CALLCONV
sha256_alloc(void)
{
    return mem_alloc(sizeof(struct SHA256_STATE));
}

int ORDO_CALLCONV
sha256_init(struct SHA256_STATE *state,
            const void *params)
{
    memcpy(state->digest, sha256_iv, SHA256_DIGEST);
    state->block_len = 0;
    state->msg_len = 0;

    return ORDO_SUCCESS;
}

void ORDO_CALLCONV
sha256_update(struct SHA256_STATE *state,
              const void *buffer,
              size_t size)
{
    state->msg_len += size;

    if (state->block_len + size >= SHA256_BLOCK)
    {
        size_t pad = (size_t)(SHA256_BLOCK - state->block_len);

        memcpy(offset(state->block, state->block_len), buffer, pad);
        sha256_compress(state->block, state->digest);
        state->block_len = 0;

        buffer = offset(buffer, pad);
        size -= pad;

        while (size >= SHA256_BLOCK)
        {
            memcpy(state->block, buffer, SHA256_BLOCK);
            sha256_compress(state->block, state->digest);

            buffer = offset(buffer, SHA256_BLOCK);
            size -= SHA256_BLOCK;
        }
    }

    memcpy(offset(state->block, state->block_len), buffer, size);
    state->block_len += size;
}

void ORDO_CALLCONV
sha256_final(struct SHA256_STATE *state,
             void *digest)
{
    /* See the MD5 code for a description of Merkle padding. */
    uint64_t len = htobe64(bytes(state->msg_len));
    uint8_t one = 0x80, zero = 0x00;
    size_t t;

    sha256_update(state, &one, sizeof(one));

    while (state->block_len != SHA256_BLOCK - sizeof(uint64_t))
    {
        sha256_update(state, &zero, sizeof(zero));
    }

    sha256_update(state, &len, sizeof(len));

    /* SHA-256 takes big-endian input, convert it back. */
    for (t = 0; t < SHA256_DIGEST / sizeof(uint32_t); ++t)
        state->digest[t] = be32toh(state->digest[t]);

    memcpy(digest, state->digest, SHA256_DIGEST);
}

void ORDO_CALLCONV
sha256_free(struct SHA256_STATE *state)
{
    mem_free(state);
}

void ORDO_CALLCONV
sha256_copy(struct SHA256_STATE *dst,
            const struct SHA256_STATE *src)
{
    memcpy(dst, src, sizeof(struct SHA256_STATE));
}

size_t ORDO_CALLCONV
sha256_query(int query, size_t value)
{
    switch(query)
    {
        case BLOCK_SIZE: return SHA256_BLOCK;
        case DIGEST_LEN: return SHA256_DIGEST;
        
        default: return 0;
    }
}
