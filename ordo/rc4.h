/**
 * @file rc4.h
 * Contains the RC4 cipher primitive interface. This is a stream cipher.
 * 
 * Header usage mode: External.
 *
 * @see rc4.c
 */

#ifndef rc4_h
#define rc4_h

#include "primitives.h"

#define RC4_KEY (2064 / 8)
#define RC4_BLOCK (8 / 8) // 8-bit block
#define RC4_TWEAK 0 // no tweak

bool RC4_KeyCheck(size_t keySize);

bool RC4_KeySchedule(void* rawKey, size_t len, void* tweak, void* key);

void RC4_Permutation(void* block, void* key);

void RC4_SetPrimitive(CIPHER_PRIMITIVE** primitive);

#endif