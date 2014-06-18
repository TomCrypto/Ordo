/*===-- primitives/stream_ciphers.h --------------------*- PUBLIC -*- H -*-===*/
/**
*** @file
*** @brief Abstraction Layer
***
*** This abstraction layer declares all the stream ciphers and also makes them
*** available to higher level modules. This does not actually do encryption at
*** all but simply abstracts the stream cipher primitives - encryption modules
*** are in the \c enc folder: \c enc_stream.h.
**/
/*===----------------------------------------------------------------------===*/

#ifndef ORDO_STREAM_CIPHERS_H
#define ORDO_STREAM_CIPHERS_H

/** @cond **/
#include "ordo/common/interface.h"
#include "ordo/primitives/stream_ciphers/stream_params.h"
/** @endcond **/

#ifdef __cplusplus
extern "C" {
#endif

/*===----------------------------------------------------------------------===*/

#define stream_init                      ordo_stream_init
#define stream_update                    ordo_stream_update
#define stream_final                     ordo_stream_final
#define stream_query                     ordo_stream_query

/*===----------------------------------------------------------------------===*/

/** Initializes a stream cipher state.
***
*** @param [in,out] state          A stream cipher state.
*** @param [in]     key            The cryptographic key to use.
*** @param [in]     key_len        The length, in bytes, of the key.
*** @param [in]     primitive      A stream cipher primitive.
*** @param [in]     params         Stream cipher specific parameters.
***
*** @returns \c #ORDO_SUCCESS on success, else an error code.
**/
ORDO_PUBLIC
int stream_init(struct STREAM_STATE *state,
                const void *key,
                size_t key_len,
                prim_t primitive, const void *params);

/** Encrypts or decrypts a buffer using a stream cipher state.
***
*** @param [in,out] state          A stream cipher state.
*** @param [in,out] buffer         The buffer to encrypt or decrypt.
*** @param [in]     len            The length, in bytes, of the buffer.
***
*** @remarks Encryption and decryption are equivalent, and are done in place.
***
*** @remarks This function is  stateful and will  update the passed state (by
***          generating  keystream material), unlike block ciphers, which are
***          deterministic permutations.
**/
ORDO_PUBLIC
void stream_update(struct STREAM_STATE *state,
                   void *buffer, size_t len);

/** Finalizes a stream cipher state.
***
*** @param [in,out] state          A stream cipher state.
**/
ORDO_PUBLIC
void stream_final(struct STREAM_STATE *state);

/** Queries a stream cipher for suitable parameters.
***
*** @param [in]     primitive      A stream cipher primitive.
*** @param [in]     query          A query code.
*** @param [in]     value          A suggested value.
***
*** @returns A suitable parameter of type \c query based on \c value.
***
*** @see query.h
**/
ORDO_PUBLIC
size_t stream_query(prim_t primitive,
                    int query, size_t value);

/*===----------------------------------------------------------------------===*/

#ifdef __cplusplus
}
#endif

#endif
