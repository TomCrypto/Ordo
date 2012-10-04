#ifndef IDENTIFICATION_H
#define IDENTIFICATION_H

/**
 * @file identification.h
 * \brief Object ID manager.
 *
 * This header contains definitions associating unique identifiers to block/stream ciphers, block cipher modes of
 * operation, compression functions, hash functions, etc... This is important because the Ordo library's high level
 * API's are based on objects (so to use the RC4 stream cipher, you would use the \c RC4() object) which are located
 * in arrays to facilitate the implementation of functions such as \c getBlockCipherByName(), and are initialized via
 * functions such as \c loadPrimitives() which should be called before using Ordo.
 *
 * Each object has its own ID, for instance the NullCipher has the ID \c BLOCK_CIPHER_NULLCIPHER (which is defined as
 * 0 since this is the most basic cipher, but this is arbitrary). This ID can then be used in functions such as
 * \c getBlockCipherByID() which will return the correct block cipher object.
 *
 * This also allows for a quick overview of what is implemented in Ordo so far.
 *
 */

/* Block ciphers. */
#define BLOCK_CIPHER_COUNT                                                                                           2

#define BLOCK_CIPHER_NULLCIPHER                                                                                      0
#define BLOCK_CIPHER_THREEFISH256                                                                                    1

/* Stream ciphers. */
#define STREAM_CIPHER_COUNT                                                                                          1

#define STREAM_CIPHER_RC4                                                                                            0

/* Block cipher modes of operation. */
#define BLOCK_CIPHER_MODE_COUNT                                                                                      5

#define BLOCK_CIPHER_MODE_ECB                                                                                        0
#define BLOCK_CIPHER_MODE_CBC                                                                                        1
#define BLOCK_CIPHER_MODE_CTR                                                                                        2
#define BLOCK_CIPHER_MODE_CFB                                                                                        3
#define BLOCK_CIPHER_MODE_OFB                                                                                        4

/* Hash functions. */
#define HASH_FUNCTION_COUNT                                                                                          3

#define HASH_FUNCTION_SHA256                                                                                         0
#define HASH_FUNCTION_MD5                                                                                            1
#define HASH_FUNCTION_SKEIN256                                                                                       2

#endif
