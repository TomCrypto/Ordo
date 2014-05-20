#include "testenv.h"
#include <string.h>
#include "ordo.h"

struct TEST_VECTOR
{
    const char *name;
    size_t key_len;
    const char *key;
    const char *input;
    const char *expected;
};

static struct TEST_VECTOR tests[] = {
{
    "Threefish-256",
    32,
    "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
    "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f",
    "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ\x01",
    "\x93\xcb\x27\x5d\xe7\x2e\xb2\x86\x60\x3c\x47\xe0\x9d\x39\x1b\xf6"
    "\xa0\xf1\x60\xab\xe3\xba\x2e\xdb\x21\xd1\x11\xff\xee\xe6\xb2\xe6"
},
{
    "Threefish-256",
    32,
    "\x47\x36\xe9\xe3\xbf\xfa\x9c\x52\x0c\xef\x1b\xda\xed\x22\xdc\x91"
    "\xca\x64\x79\xf0\x81\x70\xdd\xf6\x16\xdb\xcc\xc8\xae\x12\xfa\x43",
    "\x68\x07\xd2\x66\xa5\x26\xa2\xc6\x24\xbd\x57\x8d\x90\x9f\x95\xbe"
    "\x46\xfa\x6f\xde\x5e\xb8\x3a\xdf\x40\xc0\x7f\xff\x50\xee\x7c\x01",
    "\xfe\x7b\x7b\x36\x02\xbb\xea\xde\x76\xa1\xa0\x8a\x0e\x8a\xc1\x43"
    "\xe4\x75\x93\x69\x56\x1c\x3d\x1c\x7c\x9b\x97\xe9\x82\xcf\xb6\xf8"
},
{
    "Threefish-256",
    32,
    "\x04\xe2\xb3\x2b\x0f\x05\x31\x5e\x16\x56\xd2\x78\x25\xd5\x8d\x8b"
    "\xb9\x27\xb5\xfc\x0e\x15\x9f\x18\x8f\x4a\x4c\xbc\x70\xf8\xe4\x3d",
    "\xe4\x24\x17\xa2\x84\x31\x3c\xb4\xbe\x48\x02\xb3\xbe\x44\x7f\x62"
    "\x73\x9f\xa7\x03\x53\x40\x50\xe1\x60\xf0\xfc\x8e\xbf\xc3\x02\x01",
    "\x66\xc3\xa3\x6c\x61\x7a\x33\x1b\x5e\x8d\x92\xe8\xae\xb1\xc3\xa5"
    "\x01\x20\x96\xee\x13\x55\x5b\x26\x63\x47\xf3\x29\xf6\x10\x69\x24"
},
{
    "Threefish-256",
    32,
    "\x37\x7c\x8b\x7d\xf9\xc4\xc3\xb6\xab\x08\x60\x39\x5a\x6f\x1f\xa7"
    "\xef\x83\x9a\x2d\xdd\x42\x6d\x73\x78\x21\x02\xb4\x9a\x33\x7e\x81",
    "\x83\xc5\x9f\xdc\x09\xa4\xe7\x1a\x05\x16\xcf\xe9\x94\x07\xb0\xe9"
    "\x09\x25\xef\x84\xb6\x31\x14\x53\x2c\x4b\x2e\xdc\xf7\x81\xe1\x01",
    "\xa2\x16\x91\x95\xeb\x54\x91\x50\xa9\xb9\x0d\x10\x32\x17\xb9\xb1"
    "\x93\x9c\x16\xf2\x03\xcb\x87\xff\x14\x0a\x32\xfe\x58\x1a\x92\x7b"
},
{
    "Threefish-256",
    32,
    "\xe1\xa1\x72\xb4\xb7\x5b\x71\x98\x5f\x73\xad\x6a\x9a\x6b\x3d\x87"
    "\x67\x62\xf1\x4c\xff\x2a\x4e\x01\x9c\x35\xf5\xe7\x1c\xb6\xd9\x0b",
    "\x72\x06\xac\x5c\xb4\x7f\x1a\xbd\x12\xd7\xbf\xc1\xb5\x22\x2a\xcf"
    "\x46\x48\xe4\x18\x71\x45\x12\xbc\xf5\x9c\x8c\x08\x54\xf3\x61\x01",
    "\xd6\xd4\x7f\x0b\x49\xac\x92\xb8\x51\x6c\x84\xea\xc4\xb3\xb6\x88"
    "\x69\x0e\xc9\xba\x23\x08\x56\x40\x8d\x41\x87\x82\x2c\xa8\x1b\x34"
},
{
    "Threefish-256",
    32,
    "\x26\x30\x85\x8b\xcc\x7a\x91\x8c\x0b\x6b\x83\xa0\xfd\x5d\x38\x71"
    "\xb0\xec\x8d\x31\x68\x39\x0d\xaf\x72\xd5\xee\x34\xe4\x0b\xf2\xa7",
    "\x55\xda\xef\x3a\xb4\xc0\xb5\xd0\x0f\x4d\x31\x9d\x60\x89\xda\xda"
    "\xef\x36\x3a\xe3\x80\xd6\x6c\xc2\x89\xba\x07\x30\x1c\x52\x20\x01",
    "\x55\xc1\x5e\x0d\x1a\xca\x34\x86\xb3\x0e\x64\x61\xff\xa1\xd0\x7b"
    "\x22\xd3\x9a\xe2\xa1\xda\x44\x06\x05\xfa\xef\x1a\xed\x55\x4a\xa1"
},
{
    "Threefish-256",
    32,
    "\xd5\x01\x37\x7b\x88\x9c\x7c\xf1\x84\x69\xdd\xc8\x40\x65\x5d\xa9"
    "\xc0\x9d\x84\xe9\x23\x12\xe9\xc0\x18\xdf\xb8\x50\xed\xfe\x6d\x0c",
    "\xeb\x61\x91\x53\x34\xe9\x21\x26\xb7\xba\x75\x30\x8d\x75\x69\x2c"
    "\xdc\x08\xd5\x70\xf5\x57\x20\xbd\xde\xd6\x48\xba\x88\x75\x86\x01",
    "\xac\xd4\x96\x2c\x66\x8e\x65\x9b\x92\x48\xc1\x7f\x6d\x13\xf8\x32"
    "\xf3\x83\xec\x1b\xd9\x3b\xb7\xe4\xf1\x64\x72\x04\x38\x66\xb8\x81"
},
{
    "Threefish-256",
    32,
    "\x9c\x67\x0c\xe7\x9a\x6b\x42\xb6\x87\x2f\x91\x37\x68\x00\x08\x47"
    "\x24\xdb\xbe\xf9\xc8\xc5\x54\x0e\xf7\xdf\x16\xae\x9e\x8a\x5f\x93",
    "\x35\xd3\xbf\xbd\x2c\x0e\x3c\xa1\x11\xaa\xd9\x92\x7b\x9f\xd4\xc2"
    "\x8f\xfb\xff\xcb\x91\x06\xa7\x09\x40\x08\xd3\xea\xc9\x2e\x93\x01",
    "\xa2\xfc\x86\x82\x72\xf5\x19\x1a\xcd\xca\x9a\xc5\x7f\x8f\x18\x69"
    "\xe2\x48\xc3\x65\xb3\x9e\xf2\x7e\xfa\x50\x2c\x52\xb6\x7d\xe1\xf7"
},
{
    "Threefish-256",
    32,
    "\x7f\x98\x6e\xa4\x56\x11\x28\xba\x94\x4f\x8c\x97\x62\x75\x5c\xbd"
    "\x7e\x7e\x01\x47\xa3\x2e\x65\x89\x17\x21\x5b\x74\x45\xff\x06\x4d",
    "\xcd\x1f\x26\x8d\xf3\xd7\x36\x45\x23\x78\x51\x96\x4d\x9a\x30\xa7"
    "\x17\x1a\x1f\xd8\xe9\xc0\x4d\x7b\x6b\x20\x71\xc2\x41\x99\x64\x01",
    "\xd6\xc2\x57\xa6\xf1\x24\x89\x22\xf8\x02\xd1\xd5\x0a\xc0\xca\xfd"
    "\x62\x74\x75\xb9\x91\xe4\xf6\xe5\x53\x2e\x57\x55\xa3\x1f\x58\xfa"
},
{
    "AES",
    16,
    "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
    "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x01",
    "\x21\xea\x2b\xa3\xe4\x45\xa0\xef\x71\x0a\x7c\x26\x61\x8d\x19\x75"
},
{
    "AES",
    16,
    "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
    "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x01",
    "\x5d\x56\x9b\x5e\x2c\x7b\xac\x73\x13\xad\x79\xf3\x59\x79\x8f\xe6"
},
{
    "AES",
    24,
    "\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5"
    "\x62\xf8\xea\xd2\x52\x2c\x6b\x7b",
    "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x01",
    "\x1b\xd3\xc7\xde\x69\x51\xb0\x49\xe9\x95\x8b\x1b\xb5\x63\x2f\xca"
},
{
    "AES",
    24,
    "\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5"
    "\x62\xf8\xea\xd2\x52\x2c\x6b\x7b",
    "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x01",
    "\x07\x30\x50\xc1\x9b\x9b\xfb\xfc\x0f\xd1\x77\x2f\x0c\x3c\xac\x84"
},
{
    "AES",
    32,
    "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81"
    "\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4",
    "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x01",
    "\x80\xd9\x05\x7c\xc5\x36\x9c\x45\x7d\xdb\xc4\xd2\x07\x5e\x3d\xc5"
},
{
    "AES",
    32,
    "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81"
    "\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4",
    "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x01",
    "\x48\x13\xb1\x2d\x8c\xd8\x58\x8c\x10\x29\xd9\x17\x13\x0b\xd2\x41"
}
};

static const int vector_count = sizeof(tests) / sizeof(struct TEST_VECTOR);

static unsigned char scratch[1024];

static int check_test_vector(int index, struct TEST_VECTOR test)
{
    enum BLOCK_CIPHER cipher = block_cipher_by_name(test.name);
    if (!cipher)
    {
        lprintf(WARN, "Algorithm %s not found - skipping.", byellow(test.name));
        return 1; /* If skipping, the test passed by convention. */
    }
    else
    {
        size_t check_len = block_cipher_query(cipher, BLOCK_SIZE_Q, 0);
        struct BLOCK_STATE state;
        int err;
        
        /* We can't use ordo_enc_block, since we are testing the block
         * cipher's permutation functions - fall back to a lower level. */
        err = block_cipher_init(&state,
                                test.key, test.key_len,
                                cipher, 0);

        if (err) return 0;

        memcpy(scratch, test.input, check_len);
        block_cipher_forward(&state, scratch);

        if (memcmp(test.expected, scratch, check_len)) return 0;

        /* Now try to decrypt and see if we get back the input. */
        block_cipher_inverse(&state, scratch);

        return !memcmp(test.input, scratch, check_len);
    }
}

int test_block(void)
{
    int t;

    for (t = 0; t < vector_count; ++t)
        if (!check_test_vector(t, tests[t])) return 0;

    return 1;
}

int test_block_utilities(void)
{
    size_t t, count = block_cipher_count();

    for (t = 0; t < count; ++t)
    {
        enum BLOCK_CIPHER cipher = block_cipher_by_index(t);
        if (!cipher) return 0;
    }

    return 1;
}
