/*===-- primitives/stream_ciphers.h --------------------*- PUBLIC -*- H -*-===*/
/**
/// @file
/// @brief Abstraction Layer
///
/// This abstraction layer declares all the stream ciphers and also makes them
/// available to higher level modules. This does not actually do encryption at
/// all but simply abstracts the stream cipher primitives - encryption modules
/// are in the \c enc folder: \c enc_stream.h.
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

enum STREAM_CIPHER
{
    STREAM_UNKNOWN           = -1,
    STREAM_RC4               =  0,
    
    STREAM_COUNT
};

struct STREAM_STATE
{
    enum STREAM_CIPHER cipher;
    
    union
    {
        struct RC4_STATE rc4;
    } jmp;
};

/** Returns the name of a stream cipher primitive.
///
/// @param [in]     primitive      A stream cipher primitive.
///
/// @returns Returns the stream cipher's name.
///
/// @remarks This name can then be used in \c stream_cipher_by_name().
**/
ORDO_PUBLIC
const char *stream_cipher_name(enum STREAM_CIPHER cipher);

/** Returns a stream cipher primitive from a name.
///
/// @param name A stream cipher name.
///
/// @returns The stream cipher such that the following is true:
///          @code stream_cipher_name(retval) = name @endcode
///          or \c STREAM_UNKNOWN if no such stream cipher exists.
**/
ORDO_PUBLIC
enum STREAM_CIPHER stream_cipher_by_name(const char *name);

/** Returns a stream cipher primitive from an index.
///
/// @param [in]     index          A stream cipher index.
///
/// @returns The stream cipher  corresponding to the  provided  index, or \c 0
///          if no such stream cipher exists.
///
/// @remarks Use \c stream_cipher_count() to  obtain an  upper  bound on stream
///          cipher indices (there will be at least one).
**/
ORDO_PUBLIC
enum STREAM_CIPHER stream_cipher_by_index(size_t index);

/** Exposes the number of stream ciphers available.
///
/// @returns The number of available stream ciphers (at least one).
///
/// @remarks This is for use in enumerating stream ciphers.
**/
ORDO_PUBLIC
size_t stream_cipher_count(void);

/*===----------------------------------------------------------------------===*/

/** Initializes a stream cipher state.
///
/// @param [in]     primitive      A stream cipher primitive.
/// @param [in,out] state          A stream cipher state.
/// @param [in]     key            The cryptographic key to use.
/// @param [in]     key_len        The length, in bytes, of the key.
/// @param [in]     params         Stream cipher specific parameters.
///
/// @returns \c #ORDO_SUCCESS on success, else an error code.
**/
ORDO_PUBLIC
int stream_cipher_init(struct STREAM_STATE *state,
                       const void *key,
                       size_t key_len,
                       enum STREAM_CIPHER cipher,
                       const void *params);

/** Encrypts or decrypts a buffer using a stream cipher state.
///
/// @param [in]     primitive      A stream cipher primitive.
/// @param [in,out] state          A stream cipher state.
/// @param [in,out] buffer         The buffer to encrypt or decrypt.
/// @param [in]     len            The length, in bytes, of the buffer.
///
/// @remarks Encryption and decryption are equivalent, and are done in place.
///
/// @remarks This function is  stateful and will  update the passed state (by
///          generating  keystream material), unlike block ciphers, which are
///          deterministic permutations.
**/
ORDO_PUBLIC
void stream_cipher_update(struct STREAM_STATE *state,
                          void *buffer,
                          size_t len);

/** Finalizes a stream cipher state.
///
/// @param [in]     primitive      A stream cipher primitive.
/// @param [in,out] state          A stream cipher state.
**/
ORDO_PUBLIC
void stream_cipher_final(struct STREAM_STATE *state);

/** Performs a deep copy of one state into another.
///
/// @param [in]     primitive      A stream cipher primitive.
/// @param [out]    dst            The destination state.
/// @param [in]     src            The source state.
///
/// @remarks The destination state must have been allocated, by using the same
///          primitive(s) as the source state, and mustn't be initialized.
///
/// @remarks The source state must be initialized.
**/
ORDO_PUBLIC
void stream_cipher_copy(struct STREAM_STATE *dst,
                        const struct STREAM_STATE *src);

/** Queries a stream cipher for suitable parameters.
///
/// @param [in]     primitive      A stream cipher primitive.
/// @param [in]     query          A query code.
/// @param [in]     value          A suggested value.
///
/// @returns A suitable parameter of type \c query based on \c value.
///
/// @see query.h
**/
ORDO_PUBLIC
size_t stream_cipher_query(enum STREAM_CIPHER cipher,
                           int query, size_t value);

/*===----------------------------------------------------------------------===*/

#ifdef __cplusplus
}
#endif

#endif
