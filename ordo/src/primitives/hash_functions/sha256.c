#include <primitives/hash_functions/sha256.h>

#include <common/environment.h>
#include <common/ordo_errors.h>
#include <common/secure_mem.h>
#include <string.h>

/******************************************************************************/

/* The SHA-256 digest size. */
#define SHA256_DIGEST (32)
/* The SHA-256 block size. */
#define SHA256_BLOCK (64)

/* The SHA-256 initial state vector. */
const uint32_t sha256_initialState[8] =
{
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

/* The SHA-256 constant table. */
const uint32_t SHA256_constants[64] =
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

/* 32-bit left and right rotation. */
#define ROL(n, r) (((n) << (r)) | ((n) >> (32 - (r))))
#define ROR(n, r) (((n) >> (r)) | ((n) << (32 - (r))))

/* A SHA-256 state. */
struct SHA256_STATE
{
    uint32_t digest[8];
    uint32_t block[16];
    uint64_t blockLength;
    uint64_t messageLength;
};

struct SHA256_STATE* sha256_alloc()
{
    return secure_alloc(sizeof(struct SHA256_STATE));
}

int sha256_init(struct SHA256_STATE *state, void* params)
{
    /* Set the digest to the initial state. */
    memcpy(state->digest, sha256_initialState, SHA256_DIGEST);
    state->messageLength = 0;
    state->blockLength = 0;

    /* Ignore the parameters, since SHA-256 has none. */
    return ORDO_SUCCESS;
}

/* This is the SHA-256 compression function. */
void sha256Compress(uint32_t block[16], uint32_t digest[8])
{
    /* Temporary variables. */
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t t1, t2;
    uint32_t w[64];
    size_t t;

    /* Perform the block extension. */
    for (t = 0; t < 16; t++) w[t] = htobe32(block[t]);
    for (t = 16; t < 64; t++) w[t] = w[t - 16] + w[t - 7]
                                   + (ROR(w[t -  2], 17) ^ ROR(w[t -  2], 19) ^ (w[t -  2] >> 10))
                                   + (ROR(w[t - 15],  7) ^ ROR(w[t - 15], 18) ^ (w[t - 15] >>  3));

    /* Save the current state. */
    a = digest[0];
    b = digest[1];
    c = digest[2];
    d = digest[3];
    e = digest[4];
    f = digest[5];
    g = digest[6];
    h = digest[7];

    /* Perform the 64 SHA-256 rounds. */
    for (t = 0; t < 64; t++)
    {
        t2 = (ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        t1 = h + (ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25)) + ((e & f) ^ ((~e) & g)) + SHA256_constants[t] + w[t];

        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    /* Feed-forward the hash state. */
    digest[0] += a;
    digest[1] += b;
    digest[2] += c;
    digest[3] += d;
    digest[4] += e;
    digest[5] += f;
    digest[6] += g;
    digest[7] += h;
}

void sha256_update(struct SHA256_STATE *state, void* buffer, size_t size)
{
    /* Some variables. */
    size_t pad = 0;

    /* Increment the message length. */
    state->messageLength += size;

    /* Is the message provided long enough to complete a block? */
    if (state->blockLength + size >= SHA256_BLOCK)
    {
        /* Compute how much of the message is needed to complete the block. */
        pad = SHA256_BLOCK - state->blockLength;
        memcpy(((unsigned char*)state->block) + state->blockLength, buffer, pad);

        /* We now have a complete block which we can process. */
        sha256Compress(state->block, state->digest);
        state->blockLength = 0;

        /* Offset the message accordingly. */
        buffer = (unsigned char*)buffer + pad;
        size -= pad;

        /* At this point, the block is empty, so process complete blocks directly. */
        while (size >= SHA256_BLOCK)
        {
            /* Just process this block. */
            memcpy(state->block, buffer, SHA256_BLOCK);
            sha256Compress(state->block, state->digest);
            buffer = (unsigned char*)buffer + SHA256_BLOCK;
            size -= SHA256_BLOCK;
        }
    }

    /* If we have anything left over, just append it to the context's block field. */
    memcpy(((unsigned char*)state->block) + state->blockLength, buffer, size);
    state->blockLength += size;
}

void sha256_final(struct SHA256_STATE *state, void* digest)
{
    /* Some variables. */
    uint8_t byte = 0x80;
    size_t zeroBytes;
    uint64_t len;

    /* Save the message's length (in bits) before final processing. In BIG-ENDIAN! */
    len = htobe64(state->messageLength * 8);

    /* Append a '1' bit to the message. */
    sha256_update(state, &byte, sizeof(byte));

    /* Calculate the number of '0' bits to append. */
    zeroBytes = (SHA256_BLOCK - sizeof(uint64_t) - state->blockLength) % SHA256_BLOCK;

    /* Append that many '0' bits. */
    byte = 0x00;
    while (zeroBytes--) sha256_update(state, &byte, sizeof(byte));

    /* Append the message length (on 64 bits). */
    sha256_update(state, &len, sizeof(len));

    /* Convert the final digest to proper endianness. */
    for (len = 0; len < 8; len++) state->digest[len] = be32toh(state->digest[len]);

    /* Copy the final digest. */
    memcpy(digest, state->digest, SHA256_DIGEST);
}

void sha256_free(struct SHA256_STATE *state)
{
    secure_free(state, sizeof(struct SHA256_STATE));
}

void sha256_copy(struct SHA256_STATE *dst, struct SHA256_STATE *src)
{
    memcpy(dst, src, sizeof(struct SHA256_STATE));
}

void sha256_set_primitive(struct HASH_FUNCTION* hash)
{
    make_hash_function(hash,
                       SHA256_DIGEST,
                       SHA256_BLOCK,
                       (HASH_ALLOC)sha256_alloc,
                       (HASH_INIT)sha256_init,
                       (HASH_UPDATE)sha256_update,
                       (HASH_FINAL)sha256_final,
                       (HASH_FREE)sha256_free,
                       (HASH_COPY)sha256_copy,
                       "SHA-256");
}
