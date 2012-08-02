#ifndef ordotypes_h
#define ordotypes_h

/**
 * @file ordotypes.h
 * Contains various library-wide definitions, includes, and utility functions.
 *
 * \todo Improve code related to error handling.
 *
 */

/* Standard includes. */
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

/* Library dependencies. */
#include "securemem.h"
#include "environment.h"

// these error codes are so awful, wtf..

/*! The function succeeded. */
#define ORDO_ESUCCESS 0

/*! The function failed due to an external error. */
#define ORDO_EFAIL -1

/*! Unprocessed input was left over in the state. */
#define ORDO_LEFTOVER -2

/*! The key size provided is invalid for this primitive. */
#define ORDO_EKEYSIZE -3

/*! The padding was not recognized and decryption could not be completed. */
#define ORDO_EPADDING -4

/*! Checks whether a buffer conforms to PKCS padding.
    \param buffer The buffer to check, which should point to the first padding byte.
    \param padding The padding byte value to check the buffer against.
    \return Returns 1 if the buffer is valid, 0 otherwise. */
int padCheck(unsigned char* buffer, unsigned char padding);

/*! Performs a bitwise exclusive-or of one buffer onto another.
    \param dst The destination buffer, where the operation's result will be stored.
    \param src The source buffer, containing data to exclusive-or dst with.
    \param len The number of bytes to process in each buffer.
    \remark This is functionally equivalent to dst ^= src. Note this method has been
           optimized to process word-sized data chunks at a time, making it multiple
           times faster than a naive byte-to-byte approach. */
void xorBuffer(unsigned char* dst, unsigned char* src, size_t len);

/*! Increments a buffer of arbitrary size as if it were a len-byte integer.
    \param n Points to the buffer to increment.
    \param len The size, in bytes, of the buffer.
    \remark Carry propagation is done from left-to-right in memory storage order. */
void incBuffer(unsigned char* n, size_t len);

#endif
