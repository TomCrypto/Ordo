/*===-- test_vectors/sha256.c ----------------------------*- TEST -*- C -*-===*/
/**
*** @file
*** @brief Test Vectors
***
*** Test vectors for the SHA-256 hash function.
**/
/*===----------------------------------------------------------------------===*/

#include "testenv.h"

/*===----------------------------------------------------------------------===*/

struct TEST_VECTOR
{
    const char *in;
    size_t in_len;
    const char *out;
    size_t out_len;
};

static const struct TEST_VECTOR tests[] =
{
{
    "", 0,
    "\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99\x6f\xb9\x24"
    "\x27\xae\x41\xe4\x64\x9b\x93\x4c\xa4\x95\x99\x1b\x78\x52\xb8\x55", 32
},
{
    "A", 1,
    "\x55\x9a\xea\xd0\x82\x64\xd5\x79\x5d\x39\x09\x71\x8c\xdd\x05\xab"
    "\xd4\x95\x72\xe8\x4f\xe5\x55\x90\xee\xf3\x1a\x88\xa0\x8f\xdf\xfd", 32
},
{
    "hello", 5,
    "\x2c\xf2\x4d\xba\x5f\xb0\xa3\x0e\x26\xe8\x3b\x2a\xc5\xb9\xe2\x9e"
    "\x1b\x16\x1e\x5c\x1f\xa7\x42\x5e\x73\x04\x33\x62\x93\x8b\x98\x24", 32
},
{
    "\x6d\x65\x73\x73\x61\x67\x65\x20\x64\x69\x67\x65\x73\x74", 14,
    "\xf7\x84\x6f\x55\xcf\x23\xe1\x4e\xeb\xea\xb5\xb4\xe1\x55\x0c\xad"
    "\x5b\x50\x9e\x33\x48\xfb\xc4\xef\xa3\xa1\x41\x3d\x39\x3c\xb6\x50", 32
},
{
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
    "\x24\x8d\x6a\x61\xd2\x06\x38\xb8\xe5\xc0\x26\x93\x0c\x3e\x60\x39"
    "\xa3\x3c\xe4\x59\x64\xff\x21\x67\xf6\xec\xed\xd4\x19\xdb\x06\xc1", 32
},
{
    "\x46\x6f\x72\x20\x74\x68\x69\x73\x20\x73\x61\x6d\x70\x6c\x65\x2c"
    "\x20\x74\x68\x69\x73\x20\x36\x33\x2d\x62\x79\x74\x65\x20\x73\x74"
    "\x72\x69\x6e\x67\x20\x77\x69\x6c\x6c\x20\x62\x65\x20\x75\x73\x65"
    "\x64\x20\x61\x73\x20\x69\x6e\x70\x75\x74\x20\x64\x61\x74\x61", 63,
    "\xf0\x8a\x78\xcb\xba\xee\x08\x2b\x05\x2a\xe0\x70\x8f\x32\xfa\x1e"
    "\x50\xc5\xc4\x21\xaa\x77\x2b\xa5\xdb\xb4\x06\xa2\xea\x6b\xe3\x42", 32
},
{
    "\x54\x68\x69\x73\x20\x69\x73\x20\x65\x78\x61\x63\x74\x6c\x79\x20"
    "\x36\x34\x20\x62\x79\x74\x65\x73\x20\x6c\x6f\x6e\x67\x2c\x20\x6e"
    "\x6f\x74\x20\x63\x6f\x75\x6e\x74\x69\x6e\x67\x20\x74\x68\x65\x20"
    "\x74\x65\x72\x6d\x69\x6e\x61\x74\x69\x6e\x67\x20\x62\x79\x74\x65", 64,
    "\xab\x64\xef\xf7\xe8\x8e\x2e\x46\x16\x5e\x29\xf2\xbc\xe4\x18\x26"
    "\xbd\x4c\x7b\x35\x52\xf6\xb3\x82\xa9\xe7\xd3\xaf\x47\xc2\x45\xf8", 32
},
{
    "\xd3", 1,
    "\x28\x96\x9c\xdf\xa7\x4a\x12\xc8\x2f\x3b\xad\x96\x0b\x0b\x00\x0a"
    "\xca\x2a\xc3\x29\xde\xea\x5c\x23\x28\xeb\xc6\xf2\xba\x98\x02\xc1", 32
},
{
    "\x11\xaf", 2,
    "\x5c\xa7\x13\x3f\xa7\x35\x32\x60\x81\x55\x8a\xc3\x12\xc6\x20\xee"
    "\xca\x99\x70\xd1\xe7\x0a\x4b\x95\x53\x3d\x95\x6f\x07\x2d\x1f\x98", 32
},
{
    "\xb4\x19\x0e", 3,
    "\xdf\xf2\xe7\x30\x91\xf6\xc0\x5e\x52\x88\x96\xc4\xc8\x31\xb9\x44"
    "\x86\x53\xdc\x2f\xf0\x43\x52\x8f\x67\x69\x43\x7b\xc7\xb9\x75\xc2", 32
},
{
    "\x74\xba\x25\x21", 4,
    "\xb1\x6a\xa5\x6b\xe3\x88\x0d\x18\xcd\x41\xe6\x83\x84\xcf\x1e\xc8"
    "\xc1\x76\x80\xc4\x5a\x02\xb1\x57\x5d\xc1\x51\x89\x23\xae\x8b\x0e", 32
},
{
    "\xc2\x99\x20\x96\x82", 5,
    "\xf0\x88\x7f\xe9\x61\xc9\xcd\x3b\xea\xb9\x57\xe8\x22\x24\x94\xab"
    "\xb9\x69\xb1\xce\x4c\x65\x57\x97\x6d\xf8\xb0\xf6\xd2\x0e\x91\x66", 32
},
{
    "\xe1\xdc\x72\x4d\x56\x21", 6,
    "\xec\xa0\xa0\x60\xb4\x89\x63\x62\x25\xb4\xfa\x64\xd2\x67\xda\xbb"
    "\xe4\x42\x73\x06\x7a\xc6\x79\xf2\x08\x20\xbd\xdc\x6b\x6a\x90\xac", 32
},
{
    "\x06\xe0\x76\xf5\xa4\x42\xd5", 7,
    "\x3f\xd8\x77\xe2\x74\x50\xe6\xbb\xd5\xd7\x4b\xb8\x2f\x98\x70\xc6"
    "\x4c\x66\xe1\x09\x41\x8b\xaa\x8e\x6b\xbc\xff\x35\x5e\x28\x79\x26", 32
},
{
    "\x57\x38\xc9\x29\xc4\xf4\xcc\xb6", 8,
    "\x96\x3b\xb8\x8f\x27\xf5\x12\x77\x7a\xab\x6c\x8b\x1a\x02\xc7\x0e"
    "\xc0\xad\x65\x1d\x42\x8f\x87\x00\x36\xe1\x91\x71\x20\xfb\x48\xbf", 32
},
{
    "\x33\x34\xc5\x80\x75\xd3\xf4\x13\x9e", 9,
    "\x07\x8d\xa3\xd7\x7e\xd4\x3b\xd3\x03\x7a\x43\x3f\xd0\x34\x18\x55"
    "\x02\x37\x93\xf9\xaf\xd0\x8b\x4b\x08\xea\x1e\x55\x97\xce\xef\x20", 32
},
{
    "\x74\xcb\x93\x81\xd8\x9f\x5a\xa7\x33\x68", 10,
    "\x73\xd6\xfa\xd1\xca\xaa\x75\xb4\x3b\x21\x73\x35\x61\xfd\x39\x58"
    "\xbd\xc5\x55\x19\x4a\x03\x7c\x2a\xdd\xec\x19\xdc\x2d\x7a\x52\xbd", 32
},
{
    "\x76\xed\x24\xa0\xf4\x0a\x41\x22\x1e\xbf\xcf", 11,
    "\x04\x4c\xef\x80\x29\x01\x93\x2e\x46\xdc\x46\xb2\x54\x5e\x6c\x99"
    "\xc0\xfc\x32\x3a\x0e\xd9\x9b\x08\x1b\xda\x42\x16\x85\x7f\x38\xac", 32
},
{
    "\x9b\xaf\x69\xcb\xa3\x17\xf4\x22\xfe\x26\xa9\xa0", 12,
    "\xfe\x56\x28\x7c\xd6\x57\xe4\xaf\xc5\x0d\xba\x7a\x3a\x54\xc2\xa6"
    "\x32\x4b\x88\x6b\xec\xdc\xd1\xfa\xe4\x73\xb7\x69\xe5\x51\xa0\x9b", 32
},
{
    "\x68\x51\x1c\xdb\x2d\xbb\xf3\x53\x0d\x7f\xb6\x1c\xbc", 13,
    "\xaf\x53\x43\x04\x66\x71\x5e\x99\xa6\x02\xfc\x9f\x59\x45\x71\x9b"
    "\x04\xdd\x24\x26\x7e\x6a\x98\x47\x1f\x7a\x78\x69\xbd\x3b\x43\x13", 32
},
{
    "\xaf\x39\x7a\x8b\x8d\xd7\x3a\xb7\x02\xce\x8e\x53\xaa\x9f", 14,
    "\xd1\x89\x49\x8a\x34\x63\xb1\x8e\x84\x6b\x8a\xb1\xb4\x15\x83\xb0"
    "\xb7\xef\xc7\x89\xda\xd8\xa7\xfb\x88\x5b\xbf\x8f\xb5\xb4\x5c\x5c", 32
},
{
    "\x29\x4a\xf4\x80\x2e\x5e\x92\x5e\xb1\xc6\xcc\x9c\x72\x4f\x09", 15,
    "\xdc\xba\xf3\x35\x36\x0d\xe8\x53\xb9\xcd\xdf\xda\xfb\x90\xfa\x75"
    "\x56\x7d\x0d\x3d\x58\xaf\x8d\xb9\xd7\x64\x11\x3a\xef\x57\x01\x25", 32
},
{
    "\x0a\x27\x84\x7c\xdc\x98\xbd\x6f\x62\x22\x0b\x04\x6e\xdd\x76\x2b", 16,
    "\x80\xc2\x5e\xc1\x60\x05\x87\xe7\xf2\x8b\x18\xb1\xb1\x8e\x3c\xdc"
    "\x89\x92\x8e\x39\xca\xb3\xbc\x25\xe4\xd4\xa4\xc1\x39\xbc\xed\xc4", 32
},
{
    "\x1b\x50\x3f\xb9\xa7\x3b\x16\xad\xa3\xfc\xf1\x04\x26\x23\xae\x76"
    "\x10", 17,
    "\xd5\xc3\x03\x15\xf7\x2e\xd0\x5f\xe5\x19\xa1\xbf\x75\xab\x5f\xd0"
    "\xff\xec\x5a\xc1\xac\xb0\xda\xf6\x6b\x6b\x76\x95\x98\x59\x45\x09", 32
},
{
    "\x59\xeb\x45\xbb\xbe\xb0\x54\xb0\xb9\x73\x34\xd5\x35\x80\xce\x03"
    "\xf6\x99", 18,
    "\x32\xc3\x8c\x54\x18\x9f\x23\x57\xe9\x6b\xd7\x7e\xb0\x0c\x2b\x9c"
    "\x34\x1e\xbe\xba\xcc\x29\x45\xf9\x78\x04\xf5\x9a\x93\x23\x82\x88", 32
},
{
    "\x58\xe5\xa3\x25\x9c\xb0\xb6\xd1\x2c\x83\xf7\x23\x37\x9e\x35\xfd"
    "\x29\x8b\x60", 19,
    "\x9b\x5b\x37\x81\x6d\xe8\xfc\xdf\x3e\xc1\x0b\x74\x54\x28\x70\x8d"
    "\xf8\xf3\x91\xc5\x50\xea\x67\x46\xb2\xca\xfe\x01\x9c\x2b\x6a\xce", 32
},
{
    "\xc1\xef\x39\xce\xe5\x8e\x78\xf6\xfc\xdc\x12\xe0\x58\xb7\xf9\x02"
    "\xac\xd1\xa9\x3b", 20,
    "\x6d\xd5\x2b\x0d\x8b\x48\xcc\x81\x46\xce\xbd\x02\x16\xfb\xf5\xf6"
    "\xef\x7e\xea\xfc\x0f\xf2\xff\x9d\x14\x22\xd6\x34\x55\x55\xa1\x42", 32
},
{
    "\x9c\xab\x7d\x7d\xca\xec\x98\xcb\x3a\xc6\xc6\x4d\xd5\xd4\x47\x0d"
    "\x0b\x10\x3a\x81\x0c", 21,
    "\x44\xd3\x48\x09\xfc\x60\xd1\xfc\xaf\xa7\xf3\x7b\x79\x4d\x1d\x3a"
    "\x76\x5d\xd0\xd2\x31\x94\xeb\xbe\x34\x0f\x01\x3f\x0c\x39\xb6\x13", 32
},
{
    "\xea\x15\x7c\x02\xeb\xaf\x1b\x22\xde\x22\x1b\x53\xf2\x35\x39\x36"
    "\xd2\x35\x9d\x1e\x1c\x97", 22,
    "\x9d\xf5\xc1\x6a\x3f\x58\x04\x06\xf0\x7d\x96\x14\x93\x03\xd8\xc4"
    "\x08\x86\x9b\x32\x05\x3b\x72\x6c\xf3\xde\xfd\x24\x1e\x48\x49\x57", 32
},
{
    "\xda\x99\x9b\xc1\xf9\xc7\xac\xff\x32\x82\x8a\x73\xe6\x72\xd0\xa4"
    "\x92\xf6\xee\x89\x5c\x68\x67", 23,
    "\x67\x2b\x54\xe4\x3f\x41\xee\x77\x58\x4b\xdf\x8b\xf8\x54\xd9\x7b"
    "\x62\x52\xc9\x18\xf7\xea\x2d\x26\xbc\x40\x97\xea\x53\xa8\x8f\x10", 32
},
{
    "\x47\x99\x13\x01\x15\x6d\x1d\x97\x7c\x03\x38\xef\xbc\xad\x41\x00"
    "\x41\x33\xae\xfb\xca\x6b\xcf\x7e", 24,
    "\xfe\xeb\x4b\x2b\x59\xfe\xc8\xfd\xb1\xe5\x51\x94\xa4\x93\xd8\xc8"
    "\x71\x75\x7b\x57\x23\x67\x5e\x93\xd3\xac\x03\x4b\x38\x0b\x7f\xc9", 32
},
{
    "\x2e\x7e\xa8\x4d\xa4\xbc\x4d\x7c\xfb\x46\x3e\x3f\x2c\x86\x47\x05"
    "\x7a\xff\xf3\xfb\xec\xec\xa1\xd2\x00", 25,
    "\x76\xe3\xac\xbc\x71\x88\x36\xf2\xdf\x8a\xd2\xd0\xd2\xd7\x6f\x0c"
    "\xfa\x5f\xea\x09\x86\xbe\x91\x8f\x10\xbc\xee\x73\x0d\xf4\x41\xb9", 32
},
{
    "\x47\xc7\x70\xeb\x45\x49\xb6\xef\xf6\x38\x1d\x62\xe9\xbe\xb4\x64"
    "\xcd\x98\xd3\x41\xcc\x1c\x09\x98\x1a\x7a", 26,
    "\x67\x33\x80\x9c\x73\xe5\x36\x66\xc7\x35\xb3\xbd\x3d\xaf\x87\xeb"
    "\xc7\x7c\x72\x75\x61\x50\xa6\x16\xa1\x94\x10\x8d\x71\x23\x12\x72", 32
},
{
    "\xac\x4c\x26\xd8\xb4\x3b\x85\x79\xd8\xf6\x1c\x98\x07\x02\x6e\x83"
    "\xe9\xb5\x86\xe1\x15\x9b\xd4\x3b\x85\x19\x37", 27,
    "\x0e\x6e\x3c\x14\x3c\x3a\x5f\x7f\x38\x50\x5e\xd6\xad\xc9\xb4\x8c"
    "\x18\xed\xf6\xde\xdf\x11\x63\x5f\x6e\x8f\x9a\xc7\x3c\x39\xfe\x9e", 32
},
{
    "\x07\x77\xfc\x1e\x1c\xa4\x73\x04\xc2\xe2\x65\x69\x28\x38\x10\x9e"
    "\x26\xaa\xb9\xe5\xc4\xae\x4e\x86\x00\xdf\x4b\x1f", 28,
    "\xff\xb4\xfc\x03\xe0\x54\xf8\xec\xbc\x31\x47\x0f\xc0\x23\xbe\xdc"
    "\xd4\xa4\x06\xb9\xdd\x56\xc7\x1d\xa1\xb6\x60\xdc\xc4\x84\x2c\x65", 32
},
{
    "\x1a\x57\x25\x1c\x43\x1d\x4e\x6c\x2e\x06\xd6\x52\x46\xa2\x96\x91"
    "\x50\x71\xa5\x31\x42\x5e\xcf\x25\x59\x89\x42\x2a\x66", 29,
    "\xc6\x44\x61\x2c\xd3\x26\xb3\x8b\x1c\x68\x13\xb1\xda\xde\xd3\x44"
    "\x48\x80\x5a\xef\x31\x7c\x35\xf5\x48\xdf\xb4\xa0\xd7\x4b\x81\x06", 32
},
{
    "\x9b\x24\x5f\xda\xd9\xba\xeb\x89\x0d\x9c\x0d\x0e\xff\x81\x6e\xfb"
    "\x4c\xa1\x38\x61\x0b\xc7\xd7\x8c\xb1\xa8\x01\xed\x32\x73", 30,
    "\xc0\xe2\x9e\xee\xb0\xd3\xa7\x70\x79\x47\xe6\x23\xcd\xc7\xd1\x89"
    "\x9a\xdc\x70\xdd\x78\x61\x20\x5e\xa5\xe5\x81\x39\x54\xfb\x79\x57", 32
},
{
    "\x95\xa7\x65\x80\x9c\xaf\x30\xad\xa9\x0a\xd6\xd6\x1c\x2b\x4b\x30"
    "\x25\x0d\xf0\xa7\xce\x23\xb7\x75\x3c\x91\x87\xf4\x31\x9c\xe2", 31,
    "\xa4\x13\x9b\x74\xb1\x02\xcf\x1e\x2f\xce\x22\x9a\x6c\xd8\x4c\x87"
    "\x50\x1f\x50\xaf\xa4\xc8\x0f\xea\xcf\x7d\x8c\xf5\xed\x94\xf0\x42", 32
},
{
    "\x09\xfc\x1a\xcc\xc2\x30\xa2\x05\xe4\xa2\x08\xe6\x4a\x8f\x20\x42"
    "\x91\xf5\x81\xa1\x27\x56\x39\x2d\xa4\xb8\xc0\xcf\x5e\xf0\x2b\x95", 32,
    "\x4f\x44\xc1\xc7\xfb\xeb\xb6\xf9\x60\x18\x29\xf3\x89\x7b\xfd\x65"
    "\x0c\x56\xfa\x07\x84\x4b\xe7\x64\x89\x07\x63\x56\xac\x18\x86\xa4", 32
},
{
    "\x05\x46\xf7\xb8\x68\x2b\x5b\x95\xfd\x32\x38\x5f\xaf\x25\x85\x4c"
    "\xb3\xf7\xb4\x0c\xc8\xfa\x22\x9f\xbd\x52\xb1\x69\x34\xaa\xb3\x88"
    "\xa7", 33,
    "\xb3\x1a\xd3\xcd\x02\xb1\x0d\xb2\x82\xb3\x57\x6c\x05\x9b\x74\x6f"
    "\xb2\x4c\xa6\xf0\x9f\xef\x69\x40\x2d\xc9\x0e\xce\x74\x21\xcb\xb7", 32
},
{
    "\xb1\x2d\xb4\xa1\x02\x55\x29\xb3\xb7\xb1\xe4\x5c\x6d\xbc\x7b\xaa"
    "\x88\x97\xa0\x57\x6e\x66\xf6\x4b\xf3\xf8\x23\x61\x13\xa6\x27\x6e"
    "\xe7\x7d", 34,
    "\x1c\x38\xbf\x6b\xbf\xd3\x22\x92\xd6\x7d\x1d\x65\x1f\xd9\xd5\xb6"
    "\x23\xb6\xec\x1e\x85\x44\x06\x22\x3f\x51\xd0\xdf\x46\x96\x87\x12", 32
},
{
    "\xe6\x8c\xb6\xd8\xc1\x86\x6c\x0a\x71\xe7\x31\x3f\x83\xdc\x11\xa5"
    "\x80\x9c\xf5\xcf\xbe\xed\x1a\x58\x7c\xe9\xc2\xc9\x2e\x02\x2a\xbc"
    "\x16\x44\xbb", 35,
    "\xc2\x68\x4c\x0d\xbb\x85\xc2\x32\xb6\xda\x4f\xb5\x14\x7d\xd0\x62"
    "\x44\x29\xec\x7e\x65\x79\x91\xed\xd9\x5e\xda\x37\xa5\x87\x26\x9e", 32
},
{
    "\x4e\x3d\x8a\xc3\x6d\x61\xd9\xe5\x14\x80\x83\x11\x55\xb2\x53\xb3"
    "\x79\x69\xfe\x7e\xf4\x9d\xb3\xb3\x99\x26\xf3\xa0\x0b\x69\xa3\x67"
    "\x74\x36\x60\x00", 36,
    "\xbf\x9d\x5e\x5b\x53\x93\x05\x3f\x05\x5b\x38\x0b\xae\xd7\xe7\x92"
    "\xae\x85\xad\x37\xc0\xad\xa5\xfd\x45\x19\x54\x2c\xcc\x46\x1c\xf3", 32
},
{
    "\x03\xb2\x64\xbe\x51\xe4\xb9\x41\x86\x4f\x9b\x70\xb4\xc9\x58\xf5"
    "\x35\x5a\xac\x29\x4b\x4b\x87\xcb\x03\x7f\x11\xf8\x5f\x07\xeb\x57"
    "\xb3\xf0\xb8\x95\x50", 37,
    "\xd1\xf8\xbd\x68\x40\x01\xac\x5a\x4b\x67\xbb\xf7\x9f\x87\xde\x52"
    "\x4d\x2d\xa9\x9a\xc0\x14\xde\xc3\xe4\x18\x77\x28\xf4\x55\x74\x71", 32
},
{
    "\xd0\xfe\xfd\x96\x78\x7c\x65\xff\xa7\xf9\x10\xd6\xd0\xad\xa6\x3d"
    "\x64\xd5\xc4\x67\x99\x60\xe7\xf0\x6a\xeb\x8c\x70\xdf\xef\x95\x4f"
    "\x8e\x39\xef\xdb\x62\x9b", 38,
    "\x49\xba\x38\xdb\x85\xc2\x79\x6f\x85\xff\xd5\x7d\xd5\xec\x33\x70"
    "\x07\x41\x45\x28\xae\x33\x93\x5b\x10\x2d\x16\xa6\xb9\x1b\xa6\xc1", 32
},
{
    "\xb7\xc7\x9d\x7e\x5f\x1e\xec\xcd\xfe\xdf\x0e\x7b\xf4\x3e\x73\x0d"
    "\x44\x7e\x60\x7d\x8d\x14\x89\x82\x3d\x09\xe1\x12\x01\xa0\xb1\x25"
    "\x80\x39\xe7\xbd\x48\x75\xb1", 39,
    "\x72\x5e\x6f\x8d\x88\x8e\xba\xf9\x08\xb7\x69\x22\x59\xab\x88\x39"
    "\xc3\x24\x8e\xdd\x22\xca\x11\x5b\xb1\x3e\x02\x58\x08\x65\x47\x00", 32
},
{
    "\x64\xcd\x36\x3e\xcc\xe0\x5f\xdf\xda\x24\x86\xd0\x11\xa3\xdb\x95"
    "\xb5\x20\x6a\x19\xd3\x05\x40\x46\x81\x9d\xd0\xd3\x67\x83\x95\x5d"
    "\x7e\x5b\xf8\xba\x18\xbf\x73\x8a", 40,
    "\x32\xca\xef\x02\x4f\x84\xe9\x7c\x30\xb4\xa7\xb9\xd0\x4b\x67\x8b"
    "\x3d\x8a\x6e\xb2\x25\x9d\xff\x5b\x7f\x7c\x01\x1f\x09\x08\x45\xf8", 32
},
{
    "\x6a\xc6\xc6\x3d\x61\x8e\xaf\x00\xd9\x1c\x5e\x28\x07\xe8\x3c\x09"
    "\x39\x12\xb8\xe2\x02\xf7\x8e\x13\x97\x03\x49\x8a\x79\xc6\x06\x7f"
    "\x54\x49\x7c\x61\x27\xa2\x39\x10\xa6", 41,
    "\x4b\xb3\x3e\x7c\x69\x16\xe0\x8a\x9b\x3e\xd6\xbc\xef\x79\x0a\xaa"
    "\xee\x0d\xcf\x2e\x7a\x01\xaf\xb0\x56\x18\x2d\xea\x2d\xad\x7d\x63", 32
},
{
    "\xd2\x68\x26\xdb\x9b\xae\xaa\x89\x26\x91\xb6\x89\x00\xb9\x61\x63"
    "\x20\x8e\x80\x6a\x1d\xa0\x77\x42\x9e\x45\x4f\xa0\x11\x84\x09\x51"
    "\xa0\x31\x32\x7e\x60\x5a\xb8\x2e\xcc\xe2", 42,
    "\x3a\xc7\xac\x6b\xed\x82\xfd\xc8\xcd\x15\xb7\x46\xf0\xee\x74\x89"
    "\x15\x81\x92\xc2\x38\xf3\x71\xc1\x88\x3c\x9f\xe9\x0b\x3e\x28\x31", 32
},
{
    "\x3f\x7a\x05\x9b\x65\xd6\xcb\x02\x49\x20\x4a\xac\x10\xb9\xf1\xa4"
    "\xac\x9e\x58\x68\xad\xeb\xbe\x93\x5a\x9e\xb5\xb9\x01\x9e\x1c\x93"
    "\x8b\xfc\x4e\x5c\x53\x78\x99\x7a\x39\x47\xf2", 43,
    "\xbf\xce\x80\x95\x34\xee\xfe\x87\x12\x73\x96\x4d\x32\xf0\x91\xfe"
    "\x75\x6c\x71\xa7\xf5\x12\xef\x5f\x23\x00\xbc\xd5\x7f\x69\x9e\x74", 32
},
{
    "\x60\xff\xcb\x23\xd6\xb8\x8e\x48\x5b\x92\x0a\xf8\x1d\x10\x83\xf6"
    "\x29\x1d\x06\xac\x8c\xa3\xa9\x65\xb8\x59\x14\xbc\x2a\xdd\x40\x54"
    "\x4a\x02\x7f\xca\x93\x6b\xbd\xe8\xf3\x59\x05\x1c", 44,
    "\x1d\x26\xf3\xe0\x4f\x89\xb4\xea\xa9\xdb\xed\x92\x31\xbb\x05\x1e"
    "\xef\x2e\x83\x11\xad\x26\xfe\x53\xd0\xbf\x0b\x82\x1e\xaf\x75\x67", 32
},
{
    "\x9e\xcd\x07\xb6\x84\xbb\x9e\x0e\x66\x92\xe3\x20\xce\xc4\x51\x0c"
    "\xa7\x9f\xcd\xb3\xa2\x21\x2c\x26\xd9\x0d\xf6\x5d\xb3\x3e\x69\x2d"
    "\x07\x3c\xc1\x74\x84\x0d\xb7\x97\x50\x4e\x48\x2e\xef", 45,
    "\x0f\xfe\xb6\x44\xa4\x9e\x78\x7c\xcc\x69\x70\xfe\x29\x70\x5a\x4f"
    "\x4c\x2b\xfc\xfe\x7d\x19\x74\x1c\x15\x83\x33\xff\x69\x82\xcc\x9c", 32
},
{
    "\x9d\x64\xde\x71\x61\x89\x58\x84\xe7\xfa\x3d\x6e\x9e\xb9\x96\xe7"
    "\xeb\xe5\x11\xb0\x1f\xe1\x9c\xd4\xa6\xb3\x32\x2e\x80\xaa\xf5\x2b"
    "\xf6\x44\x7e\xd1\x85\x4e\x71\x00\x1f\x4d\x54\xf8\x93\x1d", 46,
    "\xd0\x48\xee\x15\x24\x01\x4a\xdf\x9a\x56\xe6\x0a\x38\x82\x77\xde"
    "\x19\x4c\x69\x4c\xc7\x87\xfc\x5a\x1b\x55\x4e\xa9\xf0\x7a\xbf\xdf", 32
},
{
    "\xc4\xad\x3c\x5e\x78\xd9\x17\xec\xb0\xcb\xbc\xd1\xc4\x81\xfc\x2a"
    "\xaf\x23\x2f\x7e\x28\x97\x79\xf4\x0e\x50\x4c\xc3\x09\x66\x2e\xe9"
    "\x6f\xec\xbd\x20\x64\x7e\xf0\x0e\x46\x19\x9f\xbc\x48\x2f\x46", 47,
    "\x50\xdb\xf4\x00\x66\xf8\xd2\x70\x48\x4e\xe2\xef\x66\x32\x28\x2d"
    "\xfa\x30\x0a\x85\xa8\x53\x0e\xce\xeb\x0e\x04\x27\x5e\x1c\x1e\xfd", 32
},
{
    "\x4e\xef\x51\x07\x45\x9b\xdd\xf8\xf2\x4f\xc7\x65\x6f\xd4\x89\x6d"
    "\xa8\x71\x1d\xb5\x04\x00\xc0\x16\x48\x47\xf6\x92\xb8\x86\xce\x8d"
    "\x7f\x4d\x67\x39\x50\x90\xb3\x53\x4e\xfd\x7b\x0d\x29\x8d\xa3\x4b", 48,
    "\x7c\x5d\x14\xed\x83\xda\xb8\x75\xac\x25\xce\x7f\xee\xd6\xef\x83"
    "\x7d\x58\xe7\x9d\xc6\x01\xfb\x3c\x1f\xca\x48\xd4\x46\x4e\x8b\x83", 32
},
{
    "\x04\x7d\x27\x58\xe7\xc2\xc9\x62\x3f\x9b\xdb\x93\xb6\x59\x7c\x5e"
    "\x84\xa0\xcd\x34\xe6\x10\x01\x4b\xcb\x25\xb4\x9e\xd0\x5c\x7e\x35"
    "\x6e\x98\xc7\xa6\x72\xc3\xdd\xdc\xae\xb8\x43\x17\xef\x61\x4d\x34"
    "\x2f", 49,
    "\x7d\x53\xec\xcd\x03\xda\x37\xbf\x58\xc1\x96\x2a\x8f\x0f\x70\x8a"
    "\x5c\x5c\x44\x7f\x6a\x7e\x9e\x26\x13\x7c\x16\x9d\x5b\xdd\x82\xe4", 32
},
{
    "\x3d\x83\xdf\x37\x17\x2c\x81\xaf\xd0\xde\x11\x51\x39\xfb\xf4\x39"
    "\x0c\x22\xe0\x98\xc5\xaf\x4c\x5a\xb4\x85\x24\x06\x51\x0b\xc0\xe6"
    "\xcf\x74\x17\x69\xf4\x44\x30\xc5\x27\x0f\xda\xe0\xcb\x84\x9d\x71"
    "\xcb\xab", 50,
    "\x99\xdc\x77\x2e\x91\xea\x02\xd9\xe4\x21\xd5\x52\xd6\x19\x01\x01"
    "\x6b\x9f\xd4\xad\x2d\xf4\xa8\x21\x2c\x1e\xc5\xba\x13\x89\x3a\xb2", 32
},
{
    "\x33\xfd\x9b\xc1\x7e\x2b\x27\x1f\xa0\x4c\x6b\x93\xc0\xbd\xea\xe9"
    "\x86\x54\xa7\x68\x2d\x31\xd9\xb4\xda\xb7\xe6\xf3\x2c\xd5\x8f\x2f"
    "\x14\x8a\x68\xfb\xe7\xa8\x8c\x5a\xb1\xd8\x8e\xdc\xcd\xde\xb3\x0a"
    "\xb2\x1e\x5e", 51,
    "\xce\xfd\xae\x1a\x3d\x75\xe7\x92\xe8\x69\x8d\x5e\x71\xf1\x77\xcc"
    "\x76\x13\x14\xe9\xad\x5d\xf9\x60\x2c\x6e\x60\xae\x65\xc4\xc2\x67", 32
},
{
    "\x77\xa8\x79\xcf\xa1\x1d\x7f\xca\xc7\xa8\x28\x2c\xc3\x8a\x43\xdc"
    "\xf3\x76\x43\xcc\x90\x98\x37\x21\x3b\xd6\xfd\x95\xd9\x56\xb2\x19"
    "\xa1\x40\x6c\xbe\x73\xc5\x2c\xd5\x6c\x60\x0e\x55\xb7\x5b\xc3\x7e"
    "\xa6\x96\x41\xbc", 52,
    "\xc9\x9d\x64\xfa\x4d\xad\xd4\xbc\x8a\x38\x95\x31\xc6\x8b\x45\x90"
    "\xc6\xdf\x0b\x90\x99\xc4\xd5\x83\xbc\x00\x88\x9f\xb7\xb9\x80\x08", 32
},
{
    "\x45\xa3\xe6\xb8\x65\x27\xf2\x0b\x45\x37\xf5\xaf\x96\xcf\xc5\xad"
    "\x87\x77\xa2\xdd\xe6\xcf\x75\x11\x88\x6c\x55\x90\xec\xe2\x4f\xc6"
    "\x1b\x22\x67\x39\xd2\x07\xda\xbf\xe3\x2b\xa6\xef\xd9\xff\x4c\xd5"
    "\xdb\x1b\xd5\xea\xd3", 53,
    "\x4d\x12\xa8\x49\x04\x7c\x6a\xcd\x4b\x2e\xee\x6b\xe3\x5f\xa9\x05"
    "\x1b\x02\xd2\x1d\x50\xd4\x19\x54\x30\x08\xc1\xd8\x2c\x42\x70\x72", 32
},
{
    "\x25\x36\x2a\x4b\x9d\x74\xbd\xe6\x12\x8c\x4f\xdc\x67\x23\x05\x90"
    "\x09\x47\xbc\x3a\xda\x9d\x9d\x31\x6e\xbc\xf1\x66\x7a\xd4\x36\x31"
    "\x89\x93\x72\x51\xf1\x49\xc7\x2e\x06\x4a\x48\x60\x8d\x94\x0b\x75"
    "\x74\xb1\x7f\xef\xc0\xdf", 54,
    "\xf8\xe4\xcc\xab\x6c\x97\x92\x29\xf6\x06\x6c\xc0\xcb\x0c\xfa\x81"
    "\xbb\x21\x44\x7c\x16\xc6\x87\x73\xbe\x7e\x55\x8e\x9f\x9d\x79\x8d", 32
},
{
    "\x3e\xbf\xb0\x6d\xb8\xc3\x8d\x5b\xa0\x37\xf1\x36\x3e\x11\x85\x50"
    "\xaa\xd9\x46\x06\xe2\x68\x35\xa0\x1a\xf0\x50\x78\x53\x3c\xc2\x5f"
    "\x2f\x39\x57\x3c\x04\xb6\x32\xf6\x2f\x68\xc2\x94\xab\x31\xf2\xa3"
    "\xe2\xa1\xa0\xd8\xc2\xbe\x51", 55,
    "\x65\x95\xa2\xef\x53\x7a\x69\xba\x85\x83\xdf\xbf\x7f\x5b\xec\x0a"
    "\xb1\xf9\x3c\xe4\xc8\xee\x19\x16\xef\xf4\x4a\x93\xaf\x57\x49\xc4", 32
},
{
    "\x2d\x52\x44\x7d\x12\x44\xd2\xeb\xc2\x86\x50\xe7\xb0\x56\x54\xba"
    "\xd3\x5b\x3a\x68\xee\xdc\x7f\x85\x15\x30\x6b\x49\x6d\x75\xf3\xe7"
    "\x33\x85\xdd\x1b\x00\x26\x25\x02\x4b\x81\xa0\x2f\x2f\xd6\xdf\xfb"
    "\x6e\x6d\x56\x1c\xb7\xd0\xbd\x7a", 56,
    "\xcf\xb8\x8d\x6f\xaf\x2d\xe3\xa6\x9d\x36\x19\x5a\xce\xc2\xe2\x55"
    "\xe2\xaf\x2b\x7d\x93\x39\x97\xf3\x48\xe0\x9f\x6c\xe5\x75\x83\x60", 32
},
{
    "\x4c\xac\xe4\x22\xe4\xa0\x15\xa7\x54\x92\xb3\xb3\xbb\xfb\xdf\x37"
    "\x58\xea\xff\x4f\xe5\x04\xb4\x6a\x26\xc9\x0d\xac\xc1\x19\xfa\x90"
    "\x50\xf6\x03\xd2\xb5\x8b\x39\x8c\xad\x6d\x6d\x9f\xa9\x22\xa1\x54"
    "\xd9\xe0\xbc\x43\x89\x96\x82\x74\xb0", 57,
    "\x4d\x54\xb2\xd2\x84\xa6\x79\x45\x81\x22\x4e\x08\xf6\x75\x54\x1c"
    "\x8f\xea\xb6\xee\xfa\x3a\xc1\xcf\xe5\xda\x4e\x03\xe6\x2f\x72\xe4", 32
},
{
    "\x86\x20\xb8\x6f\xbc\xaa\xce\x4f\xf3\xc2\x92\x1b\x84\x66\xdd\xd7"
    "\xba\xca\xe0\x7e\xef\xef\x69\x3c\xf1\x77\x62\xdc\xab\xb8\x9a\x84"
    "\x01\x0f\xc9\xa0\xfb\x76\xce\x1c\x26\x59\x3a\xd6\x37\xa6\x12\x53"
    "\xf2\x24\xd1\xb1\x4a\x05\xad\xdc\xca\xbe", 58,
    "\xdb\xa4\x90\x25\x6c\x97\x20\xc5\x4c\x61\x2a\x5b\xd1\xef\x57\x3c"
    "\xd5\x1d\xc1\x2b\x3e\x7b\xd8\xc6\xdb\x2e\xab\xe0\xaa\xcb\x84\x6b", 32
},
{
    "\xd1\xbe\x3f\x13\xfe\xba\xfe\xfc\x14\x41\x4d\x9f\xb7\xf6\x93\xdb"
    "\x16\xdc\x1a\xe2\x70\xc5\xb6\x47\xd8\x0d\xa8\x58\x35\x87\xc1\xad"
    "\x8c\xb8\xcb\x01\x82\x43\x24\x41\x1c\xa5\xac\xe3\xca\x22\xe1\x79"
    "\xa4\xff\x49\x86\xf3\xf2\x11\x90\xf3\xd7\xf3", 59,
    "\x02\x80\x49\x78\xeb\xa6\xe1\xde\x65\xaf\xdb\xc6\xa6\x09\x1e\xd6"
    "\xb1\xec\xee\x51\xe8\xbf\xf4\x06\x46\xa2\x51\xde\x66\x78\xb7\xef", 32
},
{
    "\xf4\x99\xcc\x3f\x6e\x3c\xf7\xc3\x12\xff\xdf\xba\x61\xb1\x26\x0c"
    "\x37\x12\x9c\x1a\xfb\x39\x10\x47\x19\x33\x67\xb7\xb2\xed\xeb\x57"
    "\x92\x53\xe5\x1d\x62\xba\x6d\x91\x1e\x7b\x81\x8c\xca\xe1\x55\x3f"
    "\x61\x46\xea\x78\x0f\x78\xe2\x21\x9f\x62\x93\x09", 60,
    "\x0b\x66\xc8\xb4\xfe\xfe\xbc\x8d\xc7\xda\x0b\xbe\xdc\x11\x14\xf2"
    "\x28\xaa\x63\xc3\x7d\x5c\x30\xe9\x1a\xb5\x00\xf3\xea\xdf\xce\xc5", 32
},
{
    "\x6d\xd6\xef\xd6\xf6\xca\xa6\x3b\x72\x9a\xa8\x18\x6e\x30\x8b\xc1"
    "\xbd\xa0\x63\x07\xc0\x5a\x2c\x0a\xe5\xa3\x68\x4e\x6e\x46\x08\x11"
    "\x74\x86\x90\xdc\x2b\x58\x77\x59\x67\xcf\xcc\x64\x5f\xd8\x20\x64"
    "\xb1\x27\x9f\xdc\xa7\x71\x80\x3d\xb9\xdc\xa0\xff\x53", 61,
    "\xc4\x64\xa7\xbf\x6d\x18\x0d\xe4\xf7\x44\xbb\x2f\xe5\xdc\x27\xa3"
    "\xf6\x81\x33\x4f\xfd\x54\xa9\x81\x46\x50\xe6\x02\x60\xa4\x78\xe3", 32
},
{
    "\x65\x11\xa2\x24\x2d\xdb\x27\x31\x78\xe1\x9a\x82\xc5\x7c\x85\xcb"
    "\x05\xa6\x88\x7f\xf2\x01\x4c\xf1\xa3\x1c\xb9\xba\x5d\xf1\x69\x5a"
    "\xad\xb2\x5c\x22\xb3\xc5\xed\x51\xc1\x0d\x04\x7d\x25\x6b\x8e\x34"
    "\x42\x84\x2a\xe4\xe6\xc5\x25\xf8\xd7\xa5\xa9\x44\xaf\x2a", 62,
    "\xd6\x85\x9c\x0b\x5a\x0b\x66\x37\x6a\x24\xf5\x6b\x2a\xb1\x04\x28"
    "\x6e\xd0\x07\x86\x34\xba\x19\x11\x2a\xce\x0d\x6d\x60\xa9\xc1\xae", 32
},
{
    "\xe2\xf7\x6e\x97\x60\x6a\x87\x2e\x31\x74\x39\xf1\xa0\x3f\xcd\x92"
    "\xe6\x32\xe5\xbd\x4e\x7c\xbc\x4e\x97\xf1\xaf\xc1\x9a\x16\xfd\xe9"
    "\x2d\x77\xcb\xe5\x46\x41\x6b\x51\x64\x0c\xdd\xb9\x2a\xf9\x96\x53"
    "\x4d\xfd\x81\xed\xb1\x7c\x44\x24\xcf\x1a\xc4\xd7\x5a\xce\xeb", 63,
    "\x18\x04\x1b\xd4\x66\x50\x83\x00\x1f\xba\x8c\x54\x11\xd2\xd7\x48"
    "\xe8\xab\xbf\xdc\xdf\xd9\x21\x8c\xb0\x2b\x68\xa7\x8e\x7d\x4c\x23", 32
},
{
    "\x5a\x86\xb7\x37\xea\xea\x8e\xe9\x76\xa0\xa2\x4d\xa6\x3e\x7e\xd7"
    "\xee\xfa\xd1\x8a\x10\x1c\x12\x11\xe2\xb3\x65\x0c\x51\x87\xc2\xa8"
    "\xa6\x50\x54\x72\x08\x25\x1f\x6d\x42\x37\xe6\x61\xc7\xbf\x4c\x77"
    "\xf3\x35\x39\x03\x94\xc3\x7f\xa1\xa9\xf9\xbe\x83\x6a\xc2\x85\x09", 64,
    "\x42\xe6\x1e\x17\x4f\xbb\x38\x97\xd6\xdd\x6c\xef\x3d\xd2\x80\x2f"
    "\xe6\x7b\x33\x19\x53\xb0\x61\x14\xa6\x5c\x77\x28\x59\xdf\xc1\xaa", 32
},
{
    "\x45\x11\x01\x25\x0e\xc6\xf2\x66\x52\x24\x9d\x59\xdc\x97\x4b\x73"
    "\x61\xd5\x71\xa8\x10\x1c\xdf\xd3\x6a\xba\x3b\x58\x54\xd3\xae\x08"
    "\x6b\x5f\xdd\x45\x97\x72\x1b\x66\xe3\xc0\xdc\x5d\x8c\x60\x6d\x96"
    "\x57\xd0\xe3\x23\x28\x3a\x52\x17\xd1\xf5\x3f\x2f\x28\x4f\x57\xb8"
    "\x5c\x8a\x61\xac\x89\x24\x71\x1f\x89\x5c\x5e\xd9\x0e\xf1\x77\x45"
    "\xed\x2d\x72\x8a\xbd\x22\xa5\xf7\xa1\x34\x79\xa4\x62\xd7\x1b\x56"
    "\xc1\x9a\x74\xa4\x0b\x65\x5c\x58\xed\xfe\x0a\x18\x8a\xd2\xcf\x46"
    "\xcb\xf3\x05\x24\xf6\x5d\x42\x3c\x83\x7d\xd1\xff\x2b\xf4\x62\xac"
    "\x41\x98\x00\x73\x45\xbb\x44\xdb\xb7\xb1\xc8\x61\x29\x8c\xdf\x61"
    "\x98\x2a\x83\x3a\xfc\x72\x8f\xae\x1e\xda\x2f\x87\xaa\x2c\x94\x80"
    "\x85\x8b\xec", 163,
    "\x3c\x59\x3a\xa5\x39\xfd\xcd\xae\x51\x6c\xdf\x2f\x15\x00\x0f\x66"
    "\x34\x18\x5c\x88\xf5\x05\xb3\x97\x75\xfb\x9a\xb1\x37\xa1\x0a\xa2", 32
},
{
    "\x6b\x91\x8f\xb1\xa5\xad\x1f\x9c\x5e\x5d\xbd\xf1\x0a\x93\xa9\xc8"
    "\xf6\xbc\xa8\x9f\x37\xe7\x9c\x9f\xe1\x2a\x57\x22\x79\x41\xb1\x73"
    "\xac\x79\xd8\xd4\x40\xcd\xe8\xc6\x4c\x4e\xbc\x84\xa4\xc8\x03\xd1"
    "\x98\xa2\x96\xf3\xde\x06\x09\x00\xcc\x42\x7f\x58\xca\x6e\xc3\x73"
    "\x08\x4f\x95\xdd\x6c\x7c\x42\x7e\xcf\xbf\x78\x1f\x68\xbe\x57\x2a"
    "\x88\xdb\xcb\xb1\x88\x58\x1a\xb2\x00\xbf\xb9\x9a\x3a\x81\x64\x07"
    "\xe7\xdd\x6d\xd2\x10\x03\x55\x4d\x4f\x7a\x99\xc9\x3e\xbf\xce\x5c"
    "\x30\x2f\xf0\xe1\x1f\x26\xf8\x3f\xe6\x69\xac\xef\xb0\xc1\xbb\xb8"
    "\xb1\xe9\x09\xbd\x14\xaa\x48\xba\x34\x45\xc8\x8b\x0e\x11\x90\xee"
    "\xf7\x65\xad\x89\x8a\xb8\xca\x2f\xe5\x07\x01\x5f\x15\x78\xf1\x0d"
    "\xce\x3c\x11\xa5\x5f\xb9\x43\x4e\xe6\xe9\xad\x6c\xc0\xfd\xc4\x68"
    "\x44\x47\xa9\xb3\xb1\x56\xb9\x08\x64\x63\x60\xf2\x4f\xec\x2d\x8f"
    "\xa6\x9e\x2c\x93\xdb\x78\x70\x8f\xcd\x2e\xef\x74\x3d\xcb\x93\x53"
    "\x81\x9b\x8d\x66\x7c\x48\xed\x54\xcd\x43\x6f\xb1\x47\x65\x98\xc4"
    "\xa1\xd7\x02\x8e\x6f\x2f\xf5\x07\x51\xdb\x36\xab\x6b\xc3\x24\x35"
    "\x15\x2a\x00\xab\xd3\xd5\x8d\x9a\x87\x70\xd9\xa3\xe5\x2d\x5a\x36"
    "\x28\xae\x3c\x9e\x03\x25", 262,
    "\x46\x50\x0b\x6a\xe1\xab\x40\xbd\xe0\x97\xef\x16\x8b\x0f\x31\x99"
    "\x04\x9b\x55\x54\x5a\x15\x88\x79\x2d\x39\xd5\x94\xf4\x93\xdc\xa7", 32
},
{
    "\x82\x82\x96\x90\xaa\x37\x33\xc6\x2b\x90\xd3\x29\x78\x86\x95\x2f"
    "\xc1\xdc\x47\x3d\x67\xbb\x7d\x6b\xb2\x99\xe0\x88\xc6\x5f\xc9\x5e"
    "\xd3\xca\x0f\x36\x8d\x11\x1d\x9f\xdc\xc9\x47\x6c\xd4\x06\x5e\xfc"
    "\xe7\xc4\x81\xbe\x59\x85\x37\xf3\xf5\x3b\xbb\xb6\xff\x67\x97\x3a"
    "\x69\x83\x74\x54\x49\x9e\x31\x39\x8b\x46\x32\x88\xe3\xaa\xfb\x8b"
    "\x06\x00\xfd\xba\x1a\x25\xaf\x80\x6b\x83\xe1\x42\x5f\x38\x4e\x9e"
    "\xac\x75\x70\xf0\xc8\x23\x98\x1b\xa2\xcd\x3d\x86\x8f\xba\x94\x64"
    "\x87\x59\x62\x39\x91\xe3\x0f\x99\x7c\x3b\xfb\x33\xd0\x19\x15\x0f"
    "\x04\x67\xa9\x14\xf1\xeb\x79\xcd\x87\x27\x10\x6d\xbf\x7d\x53\x10"
    "\xd0\x97\x59\x43\xa6\x06\x7c\xc7\x90\x29\xb0\x92\x39\x51\x14\x17"
    "\xd9\x22\xc7\xc7\xac\x3d\xfd\xd8\xa4\x1c\x52\x45\x5b\x3c\x5e\x16"
    "\x4b\x82\x89\xe1\x41\xd8\x20\x91\x0f\x17\xa9\x66\x81\x29\x74\x3d"
    "\x93\x6f\x73\x12\xe1\x60\x4b\xc3\x5f\x73\xab\x16\x4a\x3f\xdd\xfe"
    "\x5f\xe1\x9b\x1a\x4a\x9f\x23\x7f\x61\xcb\x8e\xb7\x92\xe9\x5d\x09"
    "\x9a\x14\x55\xfb\x78\x9d\x8d\x16\x22\xf6\xc5\xe9\x76\xce\xf9\x51"
    "\x73\x7e\x36\xf7\xa9\xa4\xad\x19\xee\x0d\x06\x8e\x53\xd9\xf6\x04"
    "\x57\xd9\x14\x8d\x5a\x3c\xe8\x5a\x54\x6b\x45\xc5\xc6\x31\xd9\x95"
    "\xf1\x1f\x03\x7e\x47\x2f\xe4\xe8\x1f\xa7\xb9\xf2\xac\x40\x68\xb5"
    "\x30\x88\x58\xcd\x6d\x85\x86\x16\x5c\x9b\xd6\xb3\x22\xaf\xa7\x55"
    "\x40\x8d\xa9\xb9\x0a\x87\xf3\x73\x5a\x5f\x50\xeb\x85\x68\xda\xa5"
    "\x8e\xe7\xcb\xc5\x9a\xbf\x8f\xd2\xa4\x4e\x1e\xba\x72\x92\x88\x16"
    "\xc8\x90\xd1\xb0\xdb\xf6\x00\x42\x08\xff\x73\x81\xc6\x97\x75\x5a"
    "\xda\xc0\x13\x7c\xca\x34\x2b\x16\x93", 361,
    "\x5f\x4e\x16\xa7\x2d\x6c\x98\x57\xda\x0b\xa0\x09\xcc\xac\xd4\xf2"
    "\x6d\x7f\x6b\xf6\xc1\xb7\x8a\x2e\xd3\x5e\x68\xfc\xb1\x5b\x8e\x40", 32
},
{
    "\x5f\x66\x4b\xe0\xc0\xf3\xd2\xfc\x9a\x1a\x7e\xd6\xb5\x15\xef\x9c"
    "\x52\xad\x1c\x7f\xb3\xac\xf2\xc2\xde\x94\x3e\x10\x9f\x91\xcc\x12"
    "\xcc\xad\xd0\x41\xcc\x43\x86\xf9\x5a\xb6\x16\xcf\x87\x62\xba\x25"
    "\xfe\xd3\x22\xfc\x8c\x35\x18\x09\xe0\x0c\x60\x0a\x8f\x26\xe2\x5a"
    "\x5b\xcd\x0b\xc3\xb4\x41\x70\x94\x7f\x65\xb4\xf4\x17\xb8\xac\x76"
    "\x91\x87\xc2\xee\x45\x61\x97\x82\x89\xcc\xed\x04\xc0\x36\xc3\x7f"
    "\x94\x2e\xc1\x0f\x7f\xd4\xd7\xf6\x90\x8e\x22\xed\x6c\xfd\x0f\xb8"
    "\x93\x30\xc2\xfd\xe4\x17\xb9\x56\x64\x3a\xac\xa5\x3b\xaa\xb8\xa8"
    "\xff\x38\xbd\xcd\x35\xe6\x05\x47\x15\x9b\x26\x61\x8e\x1b\x29\x12"
    "\x8a\x35\xeb\xd2\x73\x3f\xc4\xad\xf6\xbf\x67\x96\x07\x6b\x09\xfd"
    "\x25\x54\xc6\xa4\xdf\x5e\x40\xae\x97\xf3\x89\xf9\x86\xf8\x43\xad"
    "\x00\x00\x05\x15\xf9\xc0\x01\xae\xc9\xc4\xe4\x7e\x2c\x60\xfe\xa7"
    "\x8d\xe8\xa3\x3c\x84\x23\xd1\x53\x9d\xfe\x12\x5c\x5b\x7e\xa4\xb1"
    "\x7c\xf8\xd8\x6e\x7f\x84\xb8\x82\x64\xaf\xec\x06\xb3\x70\xdf\xce"
    "\xbf\x5e\x1d\x3e\x2c\x1f\x00\x5f\xaf\x24\x8b\x32\x15\x93\x96\x45"
    "\x87\x85\x2b\x83\x0c\x72\x31\x50\x4f\xe9\x47\xd6\xa3\x85\xf3\x99"
    "\x44\x1c\xfc\x52\xdf\x39\x14\xfa\x55\xcd\xba\x25\xbd\x21\x5f\x91"
    "\xa8\x0f\xc8\xff\xa8\x72\xb3\x41\x13\xdb\xbd\x95\x04\x86\x83\x31"
    "\xa3\x8c\x08\x1f\xa6\x59\x57\x4b\x18\x61\x69\xdb\x59\x0f\x48\xbe"
    "\x67\xfe\x75\x88\x5b\x6c\x87\x7d\x37\xec\x16\xeb\xde\x5a\xd7\xbe"
    "\x64\x14\x08\x4e\x88\x67\x0f\x7b\x7f\x48\x5e\xfc\xf4\x45\x99\xf4"
    "\x4c\xbb\xfb\xc6\x2e\x48\xf6\x2b\x43\x83\x19\x82\x3a\xeb\x37\x67"
    "\x10\x1e\xc6\x86\x8e\x4c\x85\xb1\x13\xea\x62\x31\x93\xab\x9a\x5a"
    "\xe0\xac\x22\x63\x28\xee\x46\x74\xbf\x0a\x90\xff\x1f\x20\xeb\x54"
    "\x2e\x11\x08\x70\xbf\xee\x01\x16\x5a\xb0\x3c\x22\x40\x29\x93\x19"
    "\xaa\x3a\xb1\x04\x52\x47\xbf\x7f\x34\xe8\x41\x0d\x96\xe1\x3a\xae"
    "\x46\x55\x97\xb4\x23\x36\xca\xd2\xde\x00\xb6\x76\x02\xa7\xcb\x58"
    "\x32\xcd\x72\x53\xb2\x39\xab\x75\x2a\x85\xf4\x52\xa6\x16\x6e\x9d"
    "\xe0\x52\x3b\xf9\xc2\x0c\x2a\x0c\x27\x43\x96\xd5", 460,
    "\x04\x4d\x82\x35\x32\x09\x2c\x22\xa4\xb4\x81\x81\xcf\xb2\xc7\x96"
    "\xe1\xf5\xb9\x8b\xcd\x71\x3a\x21\xf7\x0b\x5a\xfc\xce\xef\x1d\x73", 32
}
};

#define MAX_OUT_LEN 32

/*===----------------------------------------------------------------------===*/

static int check(const struct TEST_VECTOR *test)
{
    unsigned char out[MAX_OUT_LEN];
    struct HASH_STATE state;

    ASSERT_SUCCESS(hash_init(&state, HASH_SHA256, 0));

    hash_update(&state, test->in, test->in_len);

    hash_final(&state, out);

    ASSERT_BUF_EQ(out, test->out, test->out_len);

    return 1;
}

int test_vectors_sha256(void);
int test_vectors_sha256(void)
{
    size_t t;

    if (!prim_avail(HASH_SHA256))
        return 1;

    for (t = 0; t < ARRAY_SIZE(tests); ++t)
        if (!check(tests + t)) return 0;

    return 1;
}
