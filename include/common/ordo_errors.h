#ifndef ORDO_ERRORS_H
#define ORDO_ERRORS_H

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * @file ordo_errors.h
 * @brief Library error codes.
 *
 * This header contains declarations for errors which can occur from
 * incorrect usage of library functions.
*/

/*! The function succeeded. This is defined as zero and is returned if a
 *  function encountered no error, unless specified otherwise. */
#define ORDO_SUCCESS 0

/*! The function failed due to an external error. This often indicates
 *  failure of an external component, such as the OS-provided pseudorandom
 *  number generator. Unless specified otherwise, Ordo is not responsible
 *  for this error. */
#define ORDO_FAIL -1

/*! Unprocessed input was left over in the context. This applies to block
 *  cipher modes of operation for which padding has been disabled: if the
 *  input plaintext length is not a multiple of the cipher's block size,
 *  then the remaining incomplete block cannot be handled without padding,
 *  which is an error as it generally leads to inconsistent behavior on
 *  the part of the user. */
#define ORDO_LEFTOVER -2

/*! The key size provided is invalid for this cryptographic primitive. This
 *  occurs if you give a primitive an incorrect key size, such as feeding a
 *  128-bit key into a cipher which expects a 192-bit key. Primitives either
 *  have a range of possible key lengths (often characterized by a minimum
 *  and maximum key length, but this varies among algorithms) or only one
 *  specific key length. If you need to accept arbitrary length keys, you
 *  should consider hashing your key in some fashion before using for
 *  encryption. */
#define ORDO_KEY_SIZE -3

/*! The padding was not recognized and decryption could not be completed.
 *  This applies to block cipher modes for which padding is enabled: if
 *  the last block containing padding information is malformed, the latter
 *  will generally be unreadable and the correct message size cannot be
 *  retrieved, making correct decryption impossible. Note this may not
 *  occur all the time, as an incorrect last block generally has a 1/256
 *  chance of being a valid padding block, and no error will occur (on
 *  the other hand, the returned plaintext will be incorrect). If you must
 *  ensure the plaintext is decrypted intact, you probably want to use a
 *  MAC (Message Authentication Code) along with encryption. */
#define ORDO_PADDING -4

/*! An attempt to allocate heap memory failed - this can be due to the
 *  system being low on memory or - more likely - the process to which
 *  the library is attached has reached its memory locking quota. If
 *  the former, there is not much to be done except get more memory.
 *  If the latter, either use less locked memory (which means avoiding
 *  using \c secure_alloc for large memory buffers) or increase your
 *  process memory locking quota by acquiring higher privileges, or
 *  simply changing the quota. */
#define ORDO_ALLOC -5

/*! An invalid argument was passed to a function. Perhaps it was out of bounds. */
#define ORDO_ARG -6

#ifdef __cplusplus
}
#endif

#endif
