#ifndef identification_h
#define identification_h

/**
 * @file identification.h
 * \brief Unique identifier manager.
 *
 * This header contains definitions associating unique identifiers to primitives, modes of operations, and other objects.
 *
 */

/* Number of block cipher primitives. */
#define BLOCK_CIPHER_COUNT                      2

/* Block cipher primitive algorithms. */
#define BLOCK_CIPHER_NULLCIPHER                 0
#define BLOCK_CIPHER_THREEFISH256               1

/* Number of stream cipher primitives. */
#define STREAM_CIPHER_COUNT                     1

/* Stream cipher primitive algorithms. */
#define STREAM_CIPHER_RC4                       0

/* Number of block cipher modes of operation. */
#define BLOCK_CIPHER_MODE_COUNT                 5

/* Encryption modes of operation. */
#define BLOCK_CIPHER_MODE_ECB                   0
#define BLOCK_CIPHER_MODE_CBC                   1
#define BLOCK_CIPHER_MODE_CTR                   2
#define BLOCK_CIPHER_MODE_CFB                   3
#define BLOCK_CIPHER_MODE_OFB                   4

#endif
