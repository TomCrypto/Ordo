#ifndef HMAC_H
#define HMAC_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file hmac.h
 *
 * \brief HMAC interface.
 *
 * Interface to compute HMAC's (Hash-based Message Authentication Codes), which combine a hash function
 * with a cryptographic key securely to provide both authentication and integrity, as per RFC 2104.
 *
 * @see hmac.c
 */

#include <primitives/primitives.h>
#include <hash/hash.h>

/*! This is an HMAC context, which simply wraps a hash function context around a key. */
typedef struct HMAC_CONTEXT
{
    /*! The hash function context. */
    HASH_FUNCTION_CONTEXT* ctx;
    /*! The HMAC key. */
    uint8_t* key;
    /*! The middle digest. */
    void* digest;
} HMAC_CONTEXT;

/*! This function returns an allocated HMAC context using a given hash function.
 \param hash The hash function to use.
 \return Returns the allocated HMAC context, or 0 if an error occurred. */
HMAC_CONTEXT* hmacCreate(HASH_FUNCTION* hash);

/*! This function initializes a HMAC context, provided optional parameters.
 \param ctx An allocated HMAC context.
 \param key A pointer to the key to use.
 \param keySize The size, in bytes, of the key.
 \param hashParams This points to specific hash function parameters, set to zero for default behavior.
 \return Returns \c ORDO_ESUCCESS on success, and a negative value on error.
 \remark Note the hash parameters apply to the inner hash function only. */
int hmacInit(HMAC_CONTEXT* ctx, void* key, size_t keySize, void* hashParams);

/*! This function updates a HMAC context, feeding more data in it.
 \param ctx An allocated HMAC context.
 \param buffer A buffer containing the data.
 \param size The size, in bytes, of the buffer. */
void hmacUpdate(HMAC_CONTEXT* ctx, void* buffer, size_t size);

/*! This function finalizes a HMAC context, returning the final digest.
 \param ctx An allocated HMAC context.
 \param digest A pointer to where the digest will be written.
 \return Returns \c ORDO_ESUCCESS on success, and a negative value on error. */
int hmacFinal(HMAC_CONTEXT* ctx, void* digest);

/*! This function frees (deallocates) an initialized HMAC context.
 \param ctx The HMAC context to be freed. This context needs to at least have been allocated.
 \remark Once this function returns, the passed context may no longer be used anywhere and sensitive information will
 be wiped. Passing zero to this function is invalid and will incur a segmentation fault. Do not call this function if
 \c hmacCreate() failed, as the latter already works hard to ensure no memory is leaked if an error occurs. */
void hmacFree(HMAC_CONTEXT* ctx);

/*! This function deep-copies a context in its current state to another context. */
void hmacCopy(HMAC_CONTEXT* dst, HMAC_CONTEXT* src);

#ifdef __cplusplus
}
#endif

#endif
