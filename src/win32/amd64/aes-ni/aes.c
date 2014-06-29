/*===-- aes.c ------------------------------*- win32/amd64/aes-ni -*- C -*-===*/

#include "ordo/primitives/block_ciphers/aes.h"

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

/*===----------------------------------------------------------------------===*/

#define AES_BLOCK (bits(128))

#define key_bytes(rounds) (16 * ((rounds) + 1))

static void ExpandKey(const uint8_t *key, uint8_t *ext,
                      size_t key_len, size_t rounds) HOT_CODE;

extern void aes_forward_ASM(void *block, const void *key, uint64_t rounds);
extern void aes_inverse_ASM(void *block, const void *key, uint64_t rounds);

#if annotation
struct AES_STATE
{
    unsigned char key[336];
    unsigned rounds;
};
#endif /* annotation */

/*===----------------------------------------------------------------------===*/

int aes_init(struct AES_STATE *state,
             const void *key, size_t key_len,
             const struct AES_PARAMS *params)
{
    if (aes_query(KEY_LEN_Q, key_len) != key_len)
    {
        return ORDO_KEY_LEN;
    }

    if (params)
    {
        if (params->rounds == 0) return ORDO_ARG;
        if (params->rounds > 20) return ORDO_ARG;
        state->rounds = params->rounds;
    }
    else
    {
        /* Set the default round numbers. */
        if (key_len == 16) state->rounds = 10;
        else if (key_len == 24) state->rounds = 12;
        else if (key_len == 32) state->rounds = 14;
    }

    ExpandKey(key, state->key, key_len / 4, state->rounds);

    return ORDO_SUCCESS;
}

void aes_forward(const struct AES_STATE *state, uint8_t *block)
{
    aes_forward_ASM(block, state->key, state->rounds);
}

void aes_inverse(const struct AES_STATE *state, uint8_t *block)
{
    aes_inverse_ASM(block, state->key, state->rounds);
}

void aes_final(struct AES_STATE *state)
{
    return;
}

size_t aes_query(int query, size_t value)
{
    switch(query)
    {
        case BLOCK_SIZE_Q: return AES_BLOCK;

        case KEY_LEN_Q:
        {
            if (value <= 16) return 16;
            if (value <= 24) return 24;
            return 32;
        }

        default: return 0;
    }
}

size_t aes_bsize(void)
{
    return sizeof(struct AES_STATE);
}

/*===----------------------------------------------------------------------===*/

/* This AES implementation was obtained along with the following license: */

/* advanced encryption standard
 * author: karl malbrain, malbrain@yahoo.com

This work, including the source code, documentation
and related data, is placed into the public domain.

The orginal author is Karl Malbrain.

THIS SOFTWARE IS PROVIDED AS-IS WITHOUT WARRANTY
OF ANY KIND, NOT EVEN THE IMPLIED WARRANTY OF
MERCHANTABILITY. THE AUTHOR OF THIS SOFTWARE,
ASSUMES _NO_ RESPONSIBILITY FOR ANY CONSEQUENCE
RESULTING FROM THE USE, MODIFICATION, OR
REDISTRIBUTION OF THIS SOFTWARE.
*/

/* This is the only table needed if AES-NI is available, as it is required for
 * the key schedule algorithm. */
static const uint8_t sbox[256] =
{
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t ks[11] =
{
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

static void ExpandKey(const uint8_t *key, uint8_t *ext,
                      size_t key_len, unsigned rounds)
{
    size_t t;

    memcpy(ext, key, key_len * 4);

    for (t = key_len; t < (size_t)(4 * (rounds + 1)); ++t)
    {
        uint8_t tmp[5];

        tmp[0] = ext[4 * t - 4];
        tmp[1] = ext[4 * t - 3];
        tmp[2] = ext[4 * t - 2];
        tmp[3] = ext[4 * t - 1];

        if (!(t % key_len))
        {
            tmp[4] = tmp[3];
            tmp[3] = sbox[tmp[0]];
            tmp[0] = sbox[tmp[1]] ^ ks[t / key_len];
            tmp[1] = sbox[tmp[2]];
            tmp[2] = sbox[tmp[4]];
        }
        else if (key_len > 6 && t % key_len == 4 )
        {
            tmp[0] = sbox[tmp[0]];
            tmp[1] = sbox[tmp[1]];
            tmp[2] = sbox[tmp[2]];
            tmp[3] = sbox[tmp[3]];
        }

        ext[4 * t + 0] = ext[4 * t - 4 * key_len + 0] ^ tmp[0];
        ext[4 * t + 1] = ext[4 * t - 4 * key_len + 1] ^ tmp[1];
        ext[4 * t + 2] = ext[4 * t - 4 * key_len + 2] ^ tmp[2];
        ext[4 * t + 3] = ext[4 * t - 4 * key_len + 3] ^ tmp[3];
    }
}
