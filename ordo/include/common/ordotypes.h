#ifndef ORDOTYPES_H
#define ORDOTYPES_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file ordotypes.h
 * \brief Library-wide utility header.
 *
 * Contains various definitions, includes, and utility functions used throughout the library. For instance, this
 * contains all error definitions, a few special data types, some general-purpose routines such as exclusive-or'ing
 * two memory buffers together.
 *
 * @see ordotypes.c
 */

/* Standard includes. */
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

/* Library dependencies. */
#include <common/version.h>
#include <common/securemem.h>
#include <common/environment.h>
#include <common/identification.h>

/* The following are some composite data types used in primitives. */

/* A 128-bit structure with two 64-bit words. */
typedef struct UINT128_64 { uint64_t words[2]; } UINT128_64;

/* A 256-bit structure with four 64-bit words. */
typedef struct UINT256_64 { uint64_t words[4]; } UINT256_64;

/* Some helpful macros. */
#define min(a, b) ((a < b) ? a : b)
#define max(a, b) ((a > b) ? a : b)

/* The following are error codes. */

/*! The function succeeded. This is defined as zero and is returned if a function encountered no error, unless
 * specified otherwise. */
#define ORDO_ESUCCESS 0

/*! The function failed due to an external error. This often indicates failure of an external component, such as the
 * OS-provided pseudorandom number generator. Unless specified otherwise, Ordo is not responsible for this error. */
#define ORDO_EFAIL -1

/*! Unprocessed input was left over in the context. This applies to block cipher modes of operation for which padding
 * has been disabled: if the input plaintext length is not a multiple of the cipher's block size, then the remaining
 * incomplete block cannot be handled without padding, which is an error as it generally leads to inconsistent behavior
 * on the part of the user. */
#define ORDO_ELEFTOVER -2

/*! The key size provided is invalid for this cryptographic primitive. This occurs if you give a primitive an incorrect
 * key size, such as feeding a 128-bit key into a cipher which expects a 192-bit key. Primitives either have a range of
 * possible key lengths (often characterized by a minimum and maximum key length, but this varies among algorithms) or
 * only one specific key length. If you need to accept arbitrary length keys, you should consider hashing your key in
 * some fashion before using for encryption. */
#define ORDO_EKEYSIZE -3

/*! The padding was not recognized and decryption could not be completed. This applies to block cipher modes for which
 * padding is enabled: if the last block containing padding information is malformed, the latter will generally be
 * unreadable and the correct message size cannot be retrieved, making correct decryption impossible. Note this may not
 * occur all the time, as an incorrect last block generally has a 1/256 chance of being a valid padding block, and no
 * error will occur (on the other hand, the returned plaintext will be incorrect). If you need to ensure the plaintext
 * is decrypted intact, you probably want to use a MAC (Message Authentication Code) along with encryption. */
#define ORDO_EPADDING -4

/*! An attempt to allocate heap memory failed - this can be due to the system being low on memory or - more likely -
 * the process to which the library is attached has reached its memory locking quota. If the former, there is not much
 * to be done except get more memory. If the latter, either use less locked memory (which means avoiding using salloc
 * for large memory buffers) or increase your process memory locking quota by acquiring higher privileges, or simply
 * changing the quota. */
#define ORDO_EHEAPALLOC -5

/* The following are utility functions. */

/*! Checks whether a buffer conforms to PKCS padding.
    \param buffer The buffer to check, which should point to the first padding byte.
    \param padding The padding byte value to check the buffer against.
    \return Returns 1 if the buffer is valid, 0 otherwise. */
inline int padCheck(unsigned char* buffer, unsigned char padding);

/*! Performs a bitwise exclusive-or of one buffer onto another.
    \param dst The destination buffer, where the result will be stored.
    \param src The source buffer, containing data to exclusive-or dst with.
    \param len The number of bytes to process in each buffer.
    \remark This is conceptually equivalent to dst ^= src. Source and destination
    buffers may be identical (in which case dst will contain len zeroes). */
inline void xorBuffer(unsigned char* dst, unsigned char* src, size_t len);

/*! Increments a buffer of arbitrary size as if it were a len-byte integer.
    \param buffer Points to the buffer to increment.
    \param len The size, in bytes, of the buffer.
    \remark Carry propagation is done left-to-right in memory storage order. */
inline void incBuffer(unsigned char* buffer, size_t len);

/*! Returns a readable error message from an error code.
    \param code The error code to interpret.
    \returns A null-terminated string containing the message.
    \remark This is a placeholder convenience function used for testing only. */
char* errorMsg(int code);

/* Some byteswap definitions, for Windows, which seems to lack them. */
#if PLATFORM_WINDOWS
#define bswap_16(x) (((x) << 8) & 0xff00) | (((x) >> 8 ) & 0xff)
#define bswap_32(x) (((x) << 24) & 0xff000000)  \
                    | (((x) << 8) & 0xff0000)   \
                    | (((x) >> 8) & 0xff00)     \
                    | (((x) >> 24) & 0xff )
#define bswap_64(x) ((((x) & 0xff00000000000000ull) >> 56) \
                    | (((x) & 0x00ff000000000000ull) >> 40) \
                    | (((x) & 0x0000ff0000000000ull) >> 24) \
                    | (((x) & 0x000000ff00000000ull) >> 8) \
                    | (((x) & 0x00000000ff000000ull) << 8) \
                    | (((x) & 0x0000000000ff0000ull) << 24) \
                    | (((x) & 0x000000000000ff00ull) << 40) \
                    | (((x) & 0x00000000000000ffull) << 56))

/* This isn't correct and was hacked in to make SHA-256 work on Windows. Will be fixed soon(tm). */
#define htobe32(x) (bswap_32(x))
#define be32toh(x) (bswap_32(x))
#define htobe64(x) (bswap_64(x))
#define htole64(x) (x)
#endif

#ifdef __cplusplus
}
#endif

#endif
