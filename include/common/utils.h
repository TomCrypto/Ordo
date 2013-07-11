#ifndef ORDO_UTILS_H
#define ORDO_UTILS_H

#include <stdlib.h>
#include <stdint.h>

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * @file utils.h
 * @brief Library utility functions.
 *
 * This header provides various utility functions used internally, but which
 * may also be of use for software using the library.
*/

/*! Converts bits into bytes (rounded down to the nearest byte boundary).
 * @returns \c bits(256) returns 32 (bytes).
*/
#define bits(n) (n / 8)

/*! Converts bytes into bits.
 * @returns \c bits(32) returns 256 (bits).
*/
#define bytes(n) (n * 8)

#define min(a, b) ((a < b) ? a : b)
#define max(a, b) ((a > b) ? a : b)

/*! Checks whether a buffer conforms to PKCS padding.
 @param buffer The buffer to check, starting at the first padding byte.
 @param padding The padding byte value to check the buffer against.
 @return Returns \c 1 if the buffer is valid, \c 0 otherwise.
 @remarks PKCS padding is defined as appending \c N bytes of padding plaintext
          at the end of the message, each with binary value \c N, with
          \c N between \c 1 and the block size of the block cipher used, such
          that the length of the message plus \c N is a multiple of the block
          cipher's block size.
 @remarks As a result, the buffer needs to be at least \c padding bytes long.
*/
int pad_check(const unsigned char *buffer, uint8_t padding);

/*! Performs a bitwise exclusive-or of one buffer onto another.
 @param dst The destination buffer, where the result will be stored.
 @param src The source buffer, containing data to exclusive-or \c dst with.
 @param len The number of bytes to process in each buffer.
 @remarks This is conceptually equivalent to \c dst \c ^= \c src.
 @remarks Source and destination buffers may be the same (in which case
          the buffer will contain \c len zeroes).
*/
void xor_buffer(unsigned char *dst, const unsigned char *src, size_t len);

/*! Increments a buffer of arbitrary size as though it were a \c len byte
 *  integer stored as a byte array.
 @param buffer Points to the buffer to increment.
 @param len The size, in bytes, of the buffer.
 @remarks Carry propagation is done left-to-right in memory storage order.
*/
void inc_buffer(unsigned char *buffer, size_t len);

#ifdef __cplusplus
}
#endif

#endif
