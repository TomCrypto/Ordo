#ifndef identification_h
#define identification_h

/**
 * @file identification.h
 * \brief Unique identifier manager.
 *
 * This header contains definitions associating unique identifiers to primitives, modes of operations, and other objects.
 *
 */

/* Number of cipher primitives. */
#define CIPHER_COUNT                            3

/* Cipher primitive algorithms. */
#define CIPHER_NULLCIPHER                       0
#define CIPHER_THREEFISH256                     1
#define CIPHER_RC4                              2

/* Number of encryption modes of operation. */
#define ENCRYPT_MODE_COUNT                      6

/* Encryption modes of operation. */
#define ENCRYPT_MODE_ECB                        0
#define ENCRYPT_MODE_CBC                        1
#define ENCRYPT_MODE_CTR                        2
#define ENCRYPT_MODE_CFB                        3
#define ENCRYPT_MODE_OFB                        4
#define ENCRYPT_MODE_STREAM                     5

#endif
