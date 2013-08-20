#ifndef ORDO_IDENTIFICATION_H
#define ORDO_IDENTIFICATION_H

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * @file identification.h
 * @brief Primitive ID manager.
 *
 * This header contains definitions associating unique identifiers to block &
 * stream ciphers, block cipher modes of operation, compression functions,
 * hash functions, etc... This is important because the Ordo library's high
 * level API's are based on abstract primitives (so to use the RC4 stream
 * cipher, you would use the \c RC4() primitive which implements the base
 * stream cipher interface) which are located in arrays to facilitate the
 * implementation of functions such as \c block_cipher_by_name().
 *
 * Each primitive has its own ID, which can be used in functions such as
 * \c block_cipher_by_id(), which will return the corresponding cipher.
 *
 * This also allows for a quick overview of what is implemented in Ordo.
 *
 * @TODO: the current values are placeholders used to test whether everything
 *        using them is properly implemented, and will be replaced very soon.
*/

#define BLOCK_NULLCIPHER                                                 0x0000
#define BLOCK_THREEFISH256                                               0xE192
#define BLOCK_AES                                                        0xB077

#define STREAM_RC4                                                       0x391A

#define BLOCK_MODE_ECB                                                   0x7182
#define BLOCK_MODE_CBC                                                   0xC934
#define BLOCK_MODE_CTR                                                   0x192D
#define BLOCK_MODE_CFB                                                   0x03DD
#define BLOCK_MODE_OFB                                                   0x8190

#define HASH_SHA256                                                      0x2841
#define HASH_MD5                                                         0x48AC
#define HASH_SKEIN256                                                    0x0180

#ifdef __cplusplus
}
#endif

#endif
