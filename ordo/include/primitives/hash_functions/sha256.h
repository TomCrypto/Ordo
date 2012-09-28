#ifndef SHA256_H
#define SHA256_H

/**
 * @file sha256.h
 *
 * \brief SHA-256 hash function.
 *
 * This is the SHA-256 hash function, which produces a 256-bit digest.
 *
 * @see sha256.c
 */

#include <primitives/primitives.h>

HASH_FUNCTION_CONTEXT* SHA256_Create();

int SHA256_Init(HASH_FUNCTION_CONTEXT* ctx, void* params);

void SHA256_Update(HASH_FUNCTION_CONTEXT* ctx, void* buffer, size_t size);

void SHA256_Final(HASH_FUNCTION_CONTEXT* ctx, void* digest);

void SHA256_Free(HASH_FUNCTION_CONTEXT* ctx);

void SHA256_SetPrimitive(HASH_FUNCTION* hash);

#endif
