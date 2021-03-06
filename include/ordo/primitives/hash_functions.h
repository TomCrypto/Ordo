/*===-- primitives/hash_functions.h --------------------*- PUBLIC -*- H -*-===*/
/**
*** @file
*** @brief Abstraction Layer
***
*** This abstraction layer declares all the hash functions and also makes them
*** available to higher level modules - for a slightly more convenient wrapper
*** to this interface, you can use \c digest.h.
**/
/*===----------------------------------------------------------------------===*/

#ifndef ORDO_HASH_FUNCTIONS_H
#define ORDO_HASH_FUNCTIONS_H

/** @cond **/
#include "ordo/common/interface.h"
/** @endcond **/

#include "ordo/primitives/hash_functions/hash_params.h"

#ifdef __cplusplus
extern "C" {
#endif

/*===----------------------------------------------------------------------===*/

#define hash_init                        ordo_hash_init
#define hash_update                      ordo_hash_update
#define hash_final                       ordo_hash_final
#define hash_limits                      ordo_hash_limits
#define hash_bsize                       ordo_hash_bsize

/*===----------------------------------------------------------------------===*/

/** Initializes a hash function state.
***
*** @param [in,out] state          A hash function state.
*** @param [in]     primitive      A hash function primitive.
*** @param [in]     params         Hash function specific parameters.
***
*** @returns \c #ORDO_SUCCESS on success, else an error code.
**/
ORDO_PUBLIC
int hash_init(struct HASH_STATE *state,
              prim_t primitive, const void *params);

/** Updates a hash  function state by  appending a buffer to the  message this
*** state is to calculate the cryptographic digest of.
***
*** @param [in,out] state          An initialized hash function state.
*** @param [in]     buffer         A buffer to append to the message.
*** @param [in]     len            The length, in bytes, of the buffer.
***
*** @remarks This function has the property that doing `update(x)` followed by
***          `update(y)` is equivalent to `update(x || y)`, where `||` denotes
***          concatenation.
***
*** @remarks Passing a buffer of length zero is a no-op.
**/
ORDO_PUBLIC
void hash_update(struct HASH_STATE *state,
                 const void *buffer, size_t len);

/** Finalizes a hash function state, outputting the final digest.
***
*** @param [in,out] state          An initialized hash function state.
*** @param [out]    digest         A buffer in which to write the digest.
***
*** @remarks The \c digest buffer should  be as  large as the  hash function's
***          digest length (unless you changed it via custom parameters).
**/
ORDO_PUBLIC
void hash_final(struct HASH_STATE *state,
                void *digest);

/** Gets the limit structure for a hash function.
***
*** @param [in]     primitive      A hash function primitive.
*** @param [out]    limits         A limit structure.
***
*** @returns \c #ORDO_SUCCESS on success, else an error code.
**/
ORDO_PUBLIC
int hash_limits(prim_t primitive, struct HASH_LIMITS *limits);

/** Gets the size in bytes of a \c HASH_STATE.
***
*** @returns The size in bytes of the structure.
***
*** @remarks Binary compatibility layer.
**/
ORDO_PUBLIC
size_t hash_bsize(void);

/*===----------------------------------------------------------------------===*/

#ifdef __cplusplus
}
#endif

#endif
