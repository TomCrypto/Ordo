#ifndef ordotypes_h
#define ordotypes_h

/**
 * @file ordotypes.h
 * \brief Library-wide utility header.
 *
 * Contains various library-wide definitions, includes, and utility functions.
 *
 * \todo Improve code related to error handling.
 *
 * @see ordotypes.c
 */

/* Standard includes. */
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <time.h>

/* Library dependencies. */
#include "securemem.h"
#include "environment.h"

/* The following are some composite data types used in primitives. */

/* A 128-bit structure with two 64-bit words. */
typedef struct UINT128_64 { uint64_t words[2]; } UINT128_64;

/* A 256-bit structure with four 64-bit words. */
typedef struct UINT256_64 { uint64_t words[4]; } UINT256_64;

/* The following are error codes. */

/*! The function succeeded. This is defined as zero and is returned if a function encountered no error, unless specified otherwise. */
#define ORDO_ESUCCESS 0

/*! The function failed due to an external error. This often indicates failure of an external component, such as the OS-provided pseudorandom number generator. */
#define ORDO_EFAIL -1

/*! Unprocessed input was left over in the context. This applies to block cipher modes for which padding has been disabled: if the input plaintext length is not
 * a multiple of the cipher's block size, then the remaining incomplete block cannot be handled without padding, which is an error as it generally leads to
 * inconsistent behavior on the part of the user. */
#define ORDO_LEFTOVER -2

/*! The key size provided is invalid for this primitive. This occurs if you give a primitive an incorrect key size, such as feeding a 128-bit key into a cipher
 * which expects a 192-bit key. Primitives either have a range of possible key lengths (often characterized by a minimum and maximum key length, but this varies
 * among primitives) or one specific key length. If you need to accept arbitrary-length keys, you should consider hashing your key in some fashion. */
#define ORDO_EKEYSIZE -3

/*! The padding was not recognized and decryption could not be completed. This applies to block cipher modes for which padding is enabled: if the last block
 * containing padding information is malformed, the latter will generally be unreadable and the correct message size cannot be retrieved, making correct
 * decryption impossible. */
#define ORDO_EPADDING -4

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
    \param n Points to the buffer to increment.
    \param len The size, in bytes, of the buffer.
    \remark Carry propagation is done left-to-right in memory storage order. */
inline void incBuffer(unsigned char* n, size_t len);

/*! Returns a readable error message from an error code.
    \param code The error code to interpret.
    \returns A null-terminated string containing the message.
    \remark This is a placeholder convenience function used for testing only. */
char* errorMsg(int code);

#endif
