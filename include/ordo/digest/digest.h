/*===-- digest/digest.h --------------------------------*- PUBLIC -*- H -*-===*/
/**
*** @file
*** @brief Module
***
*** Module to compute cryptographic digests, using cryptographic hash function
*** primitives.
***
*** The advantage  of using this  digest module  instead of the  hash function
*** abstraction layer is  this keeps track of the hash  function primitive for
*** you within an opaque \c DIGEST_CTX context structure, simplifying code and
*** making it less error-prone.
***
*** Usage snippet:
***
*** @code
*** struct DIGEST_CTX ctx;
***
*** int err = digest_init(&ctx, HASH_SHA256, 0);
*** if (err) printf("Got error!\n");
***
*** const char x[] = "Hello, world!";
*** digest_update(&ctx, x, strlen(x));
***
*** unsigned char out[32];
*** digest_final(&ctx, out);
*** // out = 315f5bdb76d0...
*** @endcode
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

#define digest_init                      ordo_digest_init
#define digest_update                    ordo_digest_update
#define digest_final                     ordo_digest_final
#define digest_length                    ordo_digest_length
#define digest_bsize                     ordo_digest_bsize

/*===----------------------------------------------------------------------===*/

#define DIGEST_CTX HASH_STATE

/** Initializes a digest context.
***
*** @param [in,out] ctx            A digest context.
*** @param [in]     primitive      A hash function primitive.
*** @param [in]     params         Hash function parameters.
***
*** @returns \c #ORDO_SUCCESS on success, else an error code.
***
*** @remarks It is always valid to pass  \c 0 into \c params if you don't want
***          to use special features offered by a specific hash function.
***
*** @warning It  is \b not valid to initialize digest  contexts more than once
***          before calling \c digest_final(), this is because some algorithms
***          may allocate additional memory depending on the parameters given.
**/
#define ordo_digest_init hash_init

/** Feeds data into a digest context.
***
*** @param [in,out] ctx            An initialized digest context.
*** @param [in]     in             The data to feed into the context.
*** @param [in]     in_len         The length, in bytes, of the data.
***
*** @remarks This function has the same property as \c hash_update(), in that
***          it will concatenate the input buffers of successive calls.
***
*** @remarks It is valid to pass a  zero-length  buffer (`in_len == 0`), which
***          will do nothing (if this is the case, `in` may be \c 0).
**/
#define ordo_digest_update hash_update

/** Finalizes a  digest context, returning the digest of all the data fed into
*** it through successive \c digest_update() calls.
***
*** @param [in,out] ctx            An initialized digest context.
*** @param [out]    digest         The output buffer for the digest.
***
*** @remarks The  \c digest buffer  should  be large enough to  accomodate the
***          digest - you can query the hash function's  default digest length
***          in bytes by the \c digest_length() function, note if you provided
***          parameters which  modify the hash function's  digest length, then
***          you should already know how long the digest will be (refer to the
***          parameter's documentation).
***
*** @remarks Calling this function immediately after \c digest_init() is valid
***          and will  return the so-called "zero-length" digest, which is the
***          digest of the input of length zero.
***
*** @warning After this  function returns, you may not call \c digest_update()
***          again until you reinitialize the context using \c digest_init().
**/
#define ordo_digest_final hash_final

/** Returns the default digest length of a hash function.
***
*** @param [in]     hash           A hash function primitive.
***
*** @returns The length of the digest to be written in the \c digest parameter
***          of \c digest_final(), if no parameters which affect output length
***          were provided to \c digest_init().
**/
ORDO_PUBLIC
size_t digest_length(prim_t hash);

/** Gets the size in bytes of a \c DIGEST_CTX.
***
*** @returns The size in bytes of the structure.
***
*** @remarks Binary compatibility layer.
**/
#define ordo_digest_bsize hash_bsize

/*===----------------------------------------------------------------------===*/

#ifdef __cplusplus
}
#endif

#endif
