#ifndef ORDO_UTILS_H
#define ORDO_UTILS_H

#include <stdlib.h>
#include <stdint.h>

/******************************************************************************/

/*!
 * @file utils.h
 * @brief Library utility functions.
 *
 * This header provides various utility functions used internally, but which
 * may also be of use for software using the library.
*/

#ifdef __cplusplus
extern "C" {
#endif

/*! Converts bits into bytes (rounded down to the nearest byte boundary).
 *  @remarks As an example, \c bits(256) returns 32 (bytes).
*/
#define bits(n) (n / 8)

/*! Converts bytes into bits.
 *  @remarks As an example, \c bits(32) returns 256 (bits).
*/
#define bytes(n) (n * 8)

/*! Computes a byte-based offset.
 *  @param ptr Base pointer.
 *  @param len Offset (in bytes).
 *  @return Returns the pointer exactly \c len bytes after \c ptr.
*/
#define offset(ptr, len) ((unsigned char *)ptr + len)

#define min(a, b) ((a < b) ? a : b)
#define max(a, b) ((a > b) ? a : b)

/* Various bit-rotation operators. */
#define rol16(n, r) (((n) << (r)) | ((n) >> (16 - (r))))
#define ror16(n, r) (((n) >> (r)) | ((n) << (16 - (r))))
#define rol32(n, r) (((n) << (r)) | ((n) >> (32 - (r))))
#define ror32(n, r) (((n) >> (r)) | ((n) << (32 - (r))))
#define rol64(n, r) (((n) << (r)) | ((n) >> (64 - (r))))
#define ror64(n, r) (((n) >> (r)) | ((n) << (64 - (r))))

/*! Checks whether a buffer conforms to PKCS padding.
 *  @param buffer The buffer to check, starting at the first padding byte.
 *  @param padding The padding byte value to check the buffer against.
 *  @return Returns \c 1 if the buffer is valid, \c 0 otherwise.
 *  @remarks PKCS padding is defined as appending \c N bytes of padding
 *           plaintext at the end of the message, each with binary value
 *           \c N, with \c N between \c 1 and the block size of the block
 *           cipher used, such that the length of the message plus \c N is
 *           a multiple of the block cipher's block size.
 *  @remarks This implies the buffer must be at least \c padding bytes long.
*/
int pad_check(const unsigned char *buffer, uint8_t padding)
__attribute__((hot));

/*! Performs a bitwise exclusive-or of one buffer onto another.
 *  @param dst The destination buffer, where the result will be stored.
 *  @param src The source buffer, holding data to exclusive-or \c dst with.
 *  @param len The number of bytes to process in each buffer.
 *  @remarks This is conceptually equivalent to \c dst \c ^= \c src.
 *  @remarks Source and destination buffers may be the same (in which case
 *           the buffer will contain \c len zeroes), otherwise they may not
 *           overlap.
*/
void xor_buffer(void *dst, const void *src, size_t len)
__attribute__((hot));

/*! Increments a buffer of arbitrary size as though it were a \c len byte
 *  integer stored as a byte array.
 *  @param buffer Points to the buffer to increment.
 *  @param len The size, in bytes, of the buffer.
 *  @remarks Carry propagation is done left-to-right.
*/
void inc_buffer(unsigned char *buffer, size_t len)
__attribute__((hot));

#ifdef __cplusplus
}
#endif

#endif
