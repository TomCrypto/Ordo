#ifndef xortoy_h
#define xortoy_h

#define XORTOY_RAWKEY (256 / 8) // 256-bit key
#define XORTOY_KEY (256 / 8)
#define XORTOY_BLOCK (128 / 8) // 128-bit block
#define XORTOY_TWEAK 0 // no tweak

void XORToy_KeySchedule(void* rawKey, void* tweak, void* key);

void XORToy_Permutation(void* block, void* key);

void XORToy_Inverse(void* block, void* key);

void XORToy_SetPrimitive(CIPHER_PRIMITIVE* primitive);

#endif