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
 * The format to follow for the ID values is as follows, in bit notation
 * (least significant bit first, 16-bit ID's maximum):
 *
 * 0     : set to 1 if the primitive was implemented by a third party (not
 *         officially included in the library), and set to 0 otherwise
 *
 * 1..3  : reserved (set to 0)
 *
 * 4..7  : represents the type of primitive (see list below)
 *
 * 8..16 : arbitrary number (unique within this type group)
 *
 * The type ID's are:
 * 0: reserved
 * 1: hash function
 * 2: block cipher
 * 3: stream cipher
 * 4: block mode
 * 5..F: unused
 *
 * As an example, Threefish-256 is not provided by a third party, is a block
 * cipher, and has the arbitrary number 0x1A, so its ID is 0x1A20.
*/

#define BLOCK_NULLCIPHER                                                 0xFF20
#define BLOCK_THREEFISH256                                               0x1A20
#define BLOCK_AES                                                        0x0C20

#define STREAM_RC4                                                       0x3130

#define BLOCK_MODE_ECB                                                   0x8040
#define BLOCK_MODE_CBC                                                   0x8140
#define BLOCK_MODE_CTR                                                   0x8240
#define BLOCK_MODE_CFB                                                   0x8340
#define BLOCK_MODE_OFB                                                   0x8440

#define HASH_SHA256                                                      0x8010
#define HASH_MD5                                                         0x8110
#define HASH_SKEIN256                                                    0x8210

#ifdef __cplusplus
}
#endif

#endif
