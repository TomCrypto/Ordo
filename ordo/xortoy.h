/**
 * @file XORToy.h
 * Contains the XORToy cipher primitive interface.
 * 
 * Header usage mode: External.
 *
 * @see XORToy.c
 */

#ifndef xortoy_h
#define xortoy_h

#include "primitives.h"

#define XORTOY_RAWKEY (256 / 8) // 256-bit key
#define XORTOY_KEY (256 / 8)
#define XORTOY_BLOCK (128 / 8) // 128-bit block
#define XORTOY_TWEAK 0 // no tweak

bool XORTOY_KeyCheck(size_t keySize);

bool XORToy_KeySchedule(void* rawKey, size_t len, void* tweak, void* key);

void XORToy_Forward(void* block, void* key);

void XORToy_Inverse(void* block, void* key);

void XORToy_SetPrimitive(CIPHER_PRIMITIVE** primitive);

#endif