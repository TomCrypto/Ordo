#ifndef HASH_H
#define HASH_H

/**
 * @file hash.h
 *
 * \brief Hash function interface.
 *
 * Interface to compute cryptographic digests, using hash functions. This is a very thin wrapper around the low-level
 * functions, since hash functions are quite stateless (they do not require many parameters).
 *
 * @see hash.c
 */

#include <primitives/primitives.h>

/*! This function returns an allocated hash function context using a given hash function.
 \param hash The hash function to use.
 \return Returns the allocated hash function context, or 0 if an error occurred. */
HASH_FUNCTION_CONTEXT* hashFunctionCreate(HASH_FUNCTION* hash);

/*! This function initializes a hash function context, provided optional parameters.
 \param ctx An allocated hash function context.
 \param hashParams This points to specific hash function parameters, set to zero for default behavior.
 \return Returns \c ORDO_ESUCCESS on success, and a negative value on error. */
int hashFunctionInit(HASH_FUNCTION_CONTEXT* ctx, void* hashParams);

/*! This function updates a hash function context, feeding more data in it.
 \param ctx An allocated hash function context.
 \param buffer A buffer containing the data.
 \param size The size, in bytes, of the buffer. */
void hashFunctionUpdate(HASH_FUNCTION_CONTEXT* ctx, void* buffer, size_t size);

/*! This function finalizes a hash function context, returning the final digest.
 \param ctx An allocated hash function context.
 \param digest A pointer to where the digest will be written. */
void hashFunctionFinal(HASH_FUNCTION_CONTEXT* ctx, void* digest);

/*! This function frees (deallocates) an initialized hash function context.
 \param ctx The hash function context to be freed. This context needs to at least have been allocated.
 \remark Once this function returns, the passed context may no longer be used anywhere and sensitive information will
 be wiped. Passing zero to this function is invalid and will incur a segmentation fault. Do not call this function if
 \c hashFunctionCreate() failed, as the latter already works hard to ensure no memory is leaked if an error occurs. */
void hashFunctionFree(HASH_FUNCTION_CONTEXT* ctx);

#endif
