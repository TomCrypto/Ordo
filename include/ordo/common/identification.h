/*===-- common/identification.h ------------------------*- PUBLIC -*- H -*-===*/
/**
/// @file
/// @brief Utility
///
/// This header contains definitions associating unique identifiers to block &
/// stream ciphers,  block cipher  modes of operation,  compression functions,
/// hash functions, etc...  This is important because the  Ordo library's high
/// level API's are based on abstract primitives. Note the zero ID will always
/// stand for an error situation, e.g. primitive is not available.
///
/// This also allows for a quick overview of what is implemented in Ordo.
///
/// TODO: document ID format
**/
/*===----------------------------------------------------------------------===*/

#ifndef ORDO_IDENTIFICATION_H
#define ORDO_IDENTIFICATION_H

#ifdef __cplusplus
extern "C" {
#endif

/*===----------------------------------------------------------------------===*/

enum HASH_FUNCTION
{
    HASH_MD5                 = 0x8110,
    HASH_SHA256              = 0x8010,
    HASH_SKEIN256            = 0x8210,
};

enum STREAM_CIPHER
{
    STREAM_RC4               = 0x3130,
};

/*enum BLOCK_CIPHER
{

};*/

/*
#define BLOCK_NULLCIPHER                                                 0xFF20
#define BLOCK_THREEFISH256                                               0x1A20
#define BLOCK_AES                                                        0x0C20

#define BLOCK_MODE_ECB                                                   0x8040
#define BLOCK_MODE_CBC                                                   0x8140
#define BLOCK_MODE_CTR                                                   0x8240
#define BLOCK_MODE_CFB                                                   0x8340
#define BLOCK_MODE_OFB                                                   0x8440
*/

/*===----------------------------------------------------------------------===*/

#ifdef __cplusplus
}
#endif

#endif
