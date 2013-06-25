#ifndef ORDO_UTIL_H
#define ORDO_UTIL_H

#include <stdlib.h>

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * @file ordo_utils.h
 * @brief Library utility functions.
 *
 * This header provides various utility functions used internally, but which
 * may also be of use for software using the library.
*/

#define min(a, b) ((a < b) ? a : b)
#define max(a, b) ((a > b) ? a : b)

/*! Checks whether a buffer conforms to PKCS padding.
 @param buffer The buffer to check, starting at the first padding byte.
 @param padding The padding byte value to check the buffer against.
 @return Returns \c 1 if the buffer is valid, \c 0 otherwise.
*/
int pad_check(const unsigned char* buffer, unsigned char padding);

/*! Performs a bitwise exclusive-or of one buffer onto another.
 @param dst The destination buffer, where the result will be stored.
 @param src The source buffer, containing data to exclusive-or \c dst with.
 @param len The number of bytes to process in each buffer.
 @remarks This is conceptually equivalent to \c dst \c ^= \c src. Source and
          destination buffers may be the same (in which case the buffer
          will contain \c len zeroes).
*/
void xor_buffer(unsigned char* dst, const unsigned char* src, size_t len);

/*! Increments a buffer of arbitrary size as though it were a
 *  \c len-byte integer stored as a byte array.
 @param buffer Points to the buffer to increment.
 @param len The size, in bytes, of the buffer.
 @remarks Carry propagation is done left-to-right in memory storage order.
*/
void inc_buffer(unsigned char* buffer, size_t len);

/*! Returns a readable error message from an error code.
 @param code The error code to interpret.
 @returns A null-terminated string containing the message.
 @remarks This is a placeholder convenience function used for testing only.
*/
const char* error_msg(int code);

#ifdef __cplusplus
}
#endif

#endif
