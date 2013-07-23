#ifndef ORDO_ERRORS_H
#define ORDO_ERRORS_H

/******************************************************************************/

/*!
 * @file errors.h
 * @brief Library error codes.
 *
 * This header contains declarations for errors which can occur from incorrect
 * usage of library functions.
 *
 * External code should always use the explicit error codes instead of their
 * literal values which are subject to change, with the sole exception of
 * \c #ORDO_SUCCESS which will always be zero by convention.
*/

#ifdef __cplusplus
extern "C" {
#endif

/*! Returns a readable error message from an error code.
 *  @param code The error code to interpret.
 *  @return A null-terminated string containing the message.
 *  @remarks This function is intended for debugging purposes.
*/
const char *error_msg(int code);

enum ORDO_ERROR
{
    /*! The function succeeded.
     *  @remarks This is defined as zero and is returned if a function
     *           encountered no error, unless specified otherwise.
    */
    ORDO_SUCCESS,

    /*! The function failed due to an external error.
     *  @remarks This often indicates failure of an external component, such
     *           as the OS-provided pseudorandom number generator. Unless
     *           specified otherwise, Ordo is not responsible for this error.
    */
    ORDO_FAIL,

    /*! User input was left over unprocessed.
     *  @remarks This applies to block cipher modes of operation for which
     *           padding has been disabled. If the input plaintext length is
     *           not a multiple of the cipher's block size, then the remaining
     *           incomplete block cannot be handled without padding, which is
     *           an error as it generally leads to inconsistent behavior on
     *           the part of the user.
    */
    ORDO_LEFTOVER,

    /*! The key length provided is invalid.
     *  @remarks This occurs if you provide a key of an invalid length, such
     *           as passing a 128-bit key into a cipher which expects a
     *           192-bit key. Primitives either have a range of possible key
     *           lengths (often characterized by a minimum and maximum key
     *           length, but this varies among algorithms) or only one
     *           specific key length. If you need to accept arbitrary length
     *           keys, you should consider hashing your key in some fashion
     *           before using it for encryption, for instance using a KDF.
     *  @remarks The \c block_cipher_query() function can be used to select
     *           a suitable key length for a given block cipher via the
     *           \c #KEY_LEN query code. For stream ciphers, use
     *           \c stream_cipher_query().
    */
    ORDO_KEY_LEN,
   
    /*! The padding was not recognized and decryption could not be completed.
     *  @remarks This applies to block cipher modes for which padding is
     *           enabled. If the last block containing padding information is
     *           malformed, the padding will generally be unreadable and the
     *           correct message length cannot be retrieved, making correct
     *           decryption impossible. Note this is not guaranteed to occur
     *           if the padding block is corrupted. In other words, if
     *           \c #ORDO_PADDING is returned, the padding block is certainly
     *           corrupted, however it may still be even if the library
     *           returns success (the returned plaintext will then be
     *           incorrect). If you \b must ensure the plaintext is decrypted
     *           correctly - and you probably should - you will want to use a
     *           MAC (Message Authentication Code) along with encryption, or
     *           an authenticated block cipher mode of operation.
    */
    ORDO_PADDING,

    /*! An attempt to allocate memory failed.
     *  @remarks This occurs when the library's memory subsystem fails to
     *           allocate memory, and shouldn't occur during normal operation.
     *  @remarks This does not typically indicate the system is out of memory,
     *           as Ordo uses a dedicated high-performance memory manager.
     *           However it likely indicates a memory leak in your code.
     *  @remarks If you do not wish to use Ordo's memory allocator, you may
     *           provide your own via the \c mem_allocator() function located
     *           in the internal memory subsystem header in \c internal/mem.h.
     *           However note performance may be lower and alignement issues
     *           may cause unexpected errors.
     * @remarks If you use a custom memory allocator, this error will still
     *          be returned if your allocator fails. React accordingly.
    */
    ORDO_ALLOC,

    /*! An invalid argument was passed to a function.
     *  @remarks This is a generic error which is returned when the library
     *           finds an invalid parameter which would lead to inconsistent,
     *           undefined, or profoundly insecure behavior. Make sure your
     *           arguments are correct and do not contradict one another.
    */
    ORDO_ARG
};

#ifdef __cplusplus
}
#endif

#endif
