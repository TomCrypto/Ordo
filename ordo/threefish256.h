#ifndef threefish256_h
#define threefish256_h

#include "primitives.h"

#define THREEFISH256_RAWKEY (256 / 8) // 256-bit key
#define THREEFISH256_KEY (4864 / 8)    // 4864-bit extended key
#define THREEFISH256_BLOCK (256 / 8) // 256-bit block
#define THREEFISH256_TWEAK (128 / 8) // 128-bit tweak

bool Threefish256_KeySizeCheck(size_t keySize);

bool Threefish256_KeySchedule(void* rawKey, size_t len, void* tweak, void* key);

void Threefish256_Permutation(void* block, void* key);

void Threefish256_Inverse(void* block, void* key);

void Threefish256_SetPrimitive(CIPHER_PRIMITIVE** primitive);

#endif