#include "ordo/primitives/hash_functions/md5.h"

#include "ordo/internal/endianness.h"

#include "ordo/internal/mem.h"
#include "ordo/common/utils.h"

#include <string.h>

/******************************************************************************/

#define MD5_DIGEST (bits(128))
#define MD5_BLOCK  (bits(512))

static const uint32_t md5_iv[4] =
{
    0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
};

static void md5_compress(const uint32_t block[16], uint32_t digest[4])
__attribute__((hot));

static void md5_compress(const uint32_t block[16], uint32_t digest[4])
{
    uint32_t a = digest[0];
    uint32_t b = digest[1];
    uint32_t c = digest[2];
    uint32_t d = digest[3];

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

    a += block[ 0] + 0xF4292244 + (c ^ (b | ~d));
    a = ((a <<  6) | (a >> 26)) + b;
    d += block[ 7] + 0x432AFF97 + (b ^ (a | ~c));
    d = ((d << 10) | (d >> 22)) + a;
    c += block[14] + 0xAB9423A7 + (a ^ (d | ~b));
    c = ((c << 15) | (c >> 17)) + d;
    b += block[ 5] + 0xFC93A039 + (d ^ (c | ~a));
    b = ((b << 21) | (b >> 11)) + c;
    a += block[12] + 0x655B59C3 + (c ^ (b | ~d));
    a = ((a <<  6) | (a >> 26)) + b;
    d += block[ 3] + 0x8F0CCC92 + (b ^ (a | ~c));
    d = ((d << 10) | (d >> 22)) + a;
    c += block[10] + 0xFFEFF47D + (a ^ (d | ~b));
    c = ((c << 15) | (c >> 17)) + d;
    b += block[ 1] + 0x85845DD1 + (d ^ (c | ~a));
    b = ((b << 21) | (b >> 11)) + c;
    a += block[ 8] + 0x6FA87E4F + (c ^ (b | ~d));
    a = ((a <<  6) | (a >> 26)) + b;
    d += block[15] + 0xFE2CE6E0 + (b ^ (a | ~c));
    d = ((d << 10) | (d >> 22)) + a;
    c += block[ 6] + 0xA3014314 + (a ^ (d | ~b));
    c = ((c << 15) | (c >> 17)) + d;
    b += block[13] + 0x4E0811A1 + (d ^ (c | ~a));
    b = ((b << 21) | (b >> 11)) + c;
    a += block[ 4] + 0xF7537E82 + (c ^ (b | ~d));
    a = ((a <<  6) | (a >> 26)) + b;
    d += block[11] + 0xBD3AF235 + (b ^ (a | ~c));
    d = ((d << 10) | (d >> 22)) + a;
    c += block[ 2] + 0x2AD7D2BB + (a ^ (d | ~b));
    c = ((c << 15) | (c >> 17)) + d;
    b += block[ 9] + 0xEB86D391 + (d ^ (c | ~a));
    b = ((b << 21) | (b >> 11)) + c;

    digest[0] += a;
    digest[1] += b;
    digest[2] += c;
    digest[3] += d;
}

/******************************************************************************/

struct MD5_STATE
{
    /* Here block_len is used to track incomplete input blocks, whereas
     * msg_len stores the total message length so far (for padding). */
    uint32_t digest[4];
    uint32_t block[16];
    uint64_t block_len;
    uint64_t msg_len;
};

struct MD5_STATE *md5_alloc(void)
{
    return mem_alloc(sizeof(struct MD5_STATE));
}

int md5_init(struct MD5_STATE *state,
             const void *params)
{
    memcpy(state->digest, md5_iv, MD5_DIGEST);
    state->block_len = 0;
    state->msg_len = 0;

    return ORDO_SUCCESS;
}

void md5_update(struct MD5_STATE *state,
                const void *buffer,
                size_t size)
{
    state->msg_len += size;

    /* Do we have enough to complete a message block? */
    if (state->block_len + size >= MD5_BLOCK)
    {
        size_t pad = MD5_BLOCK - state->block_len;

        memcpy(offset(state->block, state->block_len), buffer, pad);
        md5_compress(state->block, state->digest);
        state->block_len = 0;

        buffer = offset(buffer, pad);
        size -= pad;

        /* Now the state is empty - process all full blocks. */
        while (size >= MD5_BLOCK)
        {
            memcpy(state->block, buffer, MD5_BLOCK);
            md5_compress(state->block, state->digest);

            buffer = offset(buffer, MD5_BLOCK);
            size -= MD5_BLOCK;
        }
    }

    /* Leftover input data goes into the state for later processing. */
    memcpy(offset(state->block, state->block_len), buffer, size);
    state->block_len += size;
}

void md5_final(struct MD5_STATE *state,
               void *digest)
{
    uint64_t len = htole64(bytes(state->msg_len));
    uint8_t one = 0x80, zero = 0x00;

    /* Merkle padding consists of:
     * - adding a single '1' bit.
     * - adding as many '0' bits as necessary.
     * - appending the length, as a 64-bit little endian integer, IN BITS, of
     *   the total message fed into the hash function compression function. */
    md5_update(state, &one, sizeof(one));

    while (state->block_len != MD5_BLOCK - sizeof(uint64_t))
    {
        md5_update(state, &zero, sizeof(zero));
    }

    md5_update(state, &len, sizeof(len));

    /* At this point there is no input data left in the state, everything *
     * has been processed into the digest, which we will now copy over... */
    memcpy(digest, state->digest, MD5_DIGEST);
}

void md5_free(struct MD5_STATE *state)
{
    mem_free(state);
}

void md5_copy(struct MD5_STATE *dst,
              const struct MD5_STATE *src)
{
    memcpy(dst, src, sizeof(struct MD5_STATE));
}

size_t md5_query(int query, size_t value)
{
    switch(query)
    {
        case BLOCK_SIZE: return MD5_BLOCK;
        case DIGEST_LEN: return MD5_DIGEST;
        
        default: return 0;
    }
}
