/*===-- digest/digest.h --------------------------------*- PUBLIC -*- H -*-===*/
/**
/// @file
/// @brief Module
///
/// Module to compute cryptographic digests, using cryptographic hash function
/// primitives (as a pointer to a \c HASH_FUNCTION structure).
///
/// The advantage  of using this  digest module  instead of the  hash function
/// abstraction layer is  this keeps track of the hash  function primitive for
/// you within an opaque \c DIGEST_CTX context structure, simplifying code and
/// making it less error-prone.
///
/// Usage snippet:
///
/// @code
/// const struct HASH_FUNCTION *hash = sha256();
/// struct DIGEST_CTX *ctx = digest_alloc(hash);
/// if (!ctx) printf("Failed to allocate ctx!");
///
/// int err = digest_init(ctx, 0);
/// if (err) printf("Got error!");
///
/// const char x[] = "Hello, world!";
/// digest_update(ctx, x, strlen(x));
///
/// unsigned char out[32];
/// digest_final(ctx, out);
/// // out = 315f5bdb76d0...
///
/// digest_free(ctx);
/// @endcode
**/
/*===----------------------------------------------------------------------===*/

#ifndef ORDO_DIGEST_H
#define ORDO_DIGEST_H

/** @cond **/
#include "ordo/common/interface.h"
/** @endcond **/

#include "ordo/primitives/hash_functions.h"

#ifdef __cplusplus
extern "C" {
#endif

/*===----------------------------------------------------------------------===*/

struct DIGEST_CTX
{
    struct HASH_STATE state;
};

/** Initializes a digest context.
///
/// @param [in,out] ctx            An allocated digest context.
/// @param [in]     params         Hash function parameters.
///
/// @returns \c #ORDO_SUCCESS on success, else an error code.
///
/// @remarks It is always valid to pass  \c 0 into \c params if you don't want
///          to use special features offered by a specific hash function.
///
/// @remarks It  is \b not valid to initialize digest  contexts more than once
///          before calling \c digest_final(), this is because some algorithms
///          may allocate additional memory depending on the parameters given.
**/
ORDO_PUBLIC
int digest_init(struct DIGEST_CTX *ctx, enum HASH_FUNCTION hash,
                                        const void *params);

/** Feeds data into a digest context.
///
/// @param [in,out] ctx            An initialized digest context.
/// @param [in]     in             The data to feed into the context.
/// @param [in]     in_len         The length, in bytes, of the data.
///
/// @remarks This function has the same property as \c hash_function_update(),
///          with respect to calling it in succession with different buffers.
///
/// @remarks It is valid to pass a  zero-length  buffer (`in_len == 0`), which
///          will do nothing (if this is the case, `in` may be \c 0).
**/
ORDO_PUBLIC
void digest_update(struct DIGEST_CTX *ctx,
                   const void *in, size_t in_len);

/** Finalizes a  digest context, returning the digest of all the data fed into
/// it through successive \c digest_update() calls.
///
/// @param [in,out] ctx            An initialized digest context.
/// @param [out]    digest         The output buffer for the digest.
///
/// @remarks The  \c digest buffer  should  be large enough to  accomodate the
///          digest - you can query the hash function's  default digest length
///          in bytes by the \c digest_length() function, note if you provided
///          parameters which  modify the hash function's  digest length, then
///          you should already know how long the digest will be (refer to the
///          parameter's documentation).
///
/// @remarks Calling this function immediately after \c digest_init() is valid
///          and will  return the so-called "zero-length" digest, which is the
///          digest of the input of length zero.
///
/// @remarks After this  function returns, you may not call \c digest_update()
///          again until you reinitialize the context using \c digest_init().
**/
ORDO_PUBLIC
void digest_final(struct DIGEST_CTX *ctx, void *digest);

/** Frees a digest context.
///
/// @param [in]     ctx            The digest context to be freed.
///
/// @remarks The  context need  not have been initialized, but if it has been,
///          it must have been finalized before calling this function.
///
/// @remarks Passing \c 0 to this function is valid, and will do nothing.
**/
ORDO_PUBLIC
void digest_free(struct DIGEST_CTX *ctx);

/** Performs a deep copy of one context into another.
///
/// @param [out]    dst            The destination context.
/// @param [in]     src            The source context.
///
/// @remarks The destination context should have been allocated using the same
///          primitive(s) as the source context, and mustn't be initialized.
///
/// @remarks The source context must be initialized.
///
/// @remarks This function is useful when hashing  many messages with a common
///          prefix, where the  state of the  digest context after having been
///          fed the prefix can be saved and then reused multiple times.
**/
ORDO_PUBLIC
void digest_copy(struct DIGEST_CTX *dst,
                 const struct DIGEST_CTX *src);

/** Returns the default digest length of a hash function.
///
/// @param [in]     hash           A hash function primitive.
///
/// @returns The length of the digest to be written in the \c digest parameter
///          of \c digest_final(), if no parameters which affect output length
///          were provided to \c digest_init().
**/
ORDO_PUBLIC
size_t digest_length(enum HASH_FUNCTION hash);

/*===----------------------------------------------------------------------===*/

#ifdef __cplusplus
}
#endif

#endif
