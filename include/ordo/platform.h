#ifndef ORDO_PLATFORM_H
#define ORDO_PLATFORM_H

#define CMAX(a, b) ((a) > (b) ? (a) : (b))

//#define BLSZ_HASH CMAX(32, CMAX(

struct RC4_STATE
{
    uint8_t i;
    uint8_t j;
    uint8_t s[256];
};

struct MD5_STATE
{
    /* Here block_len is used to track incomplete input blocks, whereas
     * msg_len stores the total message length so far (for padding). */
    uint32_t digest[4];
    uint32_t block[16];
    uint64_t block_len;
    uint64_t msg_len;
};

struct SHA256_STATE
{
    uint32_t digest[8];
    uint32_t block[16];
    uint64_t block_len;
    uint64_t msg_len;
};

struct SKEIN256_STATE
{
    uint64_t state[4];
    uint64_t block[4];
    uint64_t block_len;
    uint64_t msg_len;
    uint64_t out_len;
    unsigned char cipher[2048];
};

#endif
