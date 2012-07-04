#ifndef identity_h
#define identity_h

#define IDENTITY_RAWKEY (256 / 8) // 256-bit key
#define IDENTITY_KEY (256 / 8)
#define IDENTITY_BLOCK (128 / 8) // 128-bit block
#define IDENTITY_TWEAK 0 // no tweak

void Identity_KeySchedule(void* rawKey, void* tweak, void* key);

void Identity_Permutation(void* block, void* key);

void Identity_Inverse(void* block, void* key);

void Identity_SetPrimitive(CIPHER_PRIMITIVE** primitive);

#endif