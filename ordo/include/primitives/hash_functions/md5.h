#ifndef MD5_H
#define MD5_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file md5.h
 *
 * \brief MD5 hash function.
 *
 * This is the MD5 hash function, which produces a 128-bit digest.
 *
 * @see md5.c
 */

#include <primitives/primitives.h>

HASH_FUNCTION_CONTEXT* MD5_Create();

int MD5_Init(HASH_FUNCTION_CONTEXT* ctx, void* params);

void MD5_Update(HASH_FUNCTION_CONTEXT* ctx, void* buffer, size_t size);

void MD5_Final(HASH_FUNCTION_CONTEXT* ctx, void* digest);

void MD5_Free(HASH_FUNCTION_CONTEXT* ctx);

void MD5_SetPrimitive(HASH_FUNCTION* hash);

#ifdef __cplusplus
}
#endif

#endif
