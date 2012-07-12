/**
 * @file Threefish256.h
 * Contains the Threefish-256 cipher primitive interface.
 * 
 * Header usage mode: External.
 *
 * @see Threefish256.c
 */

#ifndef threefish256_h
#define threefish256_h

#include "primitives.h"

#define THREEFISH256_KEY (4864 / 8)    // 4864-bit extended key
#define THREEFISH256_BLOCK (256 / 8) // 256-bit block
#define THREEFISH256_TWEAK (128 / 8) // 128-bit tweak

bool Threefish256_KeyCheck(size_t keySize);

bool Threefish256_KeySchedule(void* rawKey, size_t len, void* tweak, void* key);

void Threefish256_Forward(void* block, void* key);

void Threefish256_Inverse(void* block, void* key);

void Threefish256_SetPrimitive(CIPHER_PRIMITIVE** primitive);

#endif