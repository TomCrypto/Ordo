#ifndef ORDO_IDENTIFICATION_H
#define ORDO_IDENTIFICATION_H

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file identification.h
 * \brief Object ID manager.
 *
 * This header contains definitions associating unique identifiers to block &
 * stream ciphers, block cipher modes of operation, compression functions,
 * hash functions, etc... This is important because the Ordo library's high
 * level API's are based on objects (so to use the RC4 stream cipher, you would
 * use the \c RC4() object) which are located in arrays to facilitate the
 * implementation of functions such as \c block_cipher_by_name(), and are
 * initialized via functions such as \c load_primitives() which should be
 * called before using Ordo (unless working in a constrained environment).
 *
 * Each object has its own ID, for instance the NullCipher has the ID
 * \c BLOCK_CIPHER_NULLCIPHER (which is defined as \c 0 since this is the most
 * basic cipher, but this is arbitrary). This ID can then be used in functions
 * such as \c block_cipher_by_id() which will return the correct block cipher
 * object.
 *
 * This also allows for a quick overview of what is implemented in Ordo so far.
*/

#define BLOCK_COUNT                                                           3

#define BLOCK_NULLCIPHER                                                      0
#define BLOCK_THREEFISH256                                                    1
#define BLOCK_AES                                                             2

#define STREAM_COUNT                                                          1

#define STREAM_RC4                                                            0

#define BLOCK_MODE_COUNT                                                      5

#define BLOCK_MODE_ECB                                                        0
#define BLOCK_MODE_CBC                                                        1
#define BLOCK_MODE_CTR                                                        2
#define BLOCK_MODE_CFB                                                        3
#define BLOCK_MODE_OFB                                                        4

#define HASH_COUNT                                                            3

#define HASH_SHA256                                                           0
#define HASH_MD5                                                              1
#define HASH_SKEIN256                                                         2

#ifdef __cplusplus
}
#endif

#endif
