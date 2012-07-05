#ifndef threefish_h
#define threefish_h

#define THREEFISH_RAWKEY (256 / 8) // 256-bit key
#define THREEFISH_KEY (4864 / 8)    // 4864-bit extended key
#define THREEFISH_BLOCK (256 / 8) // 256-bit block
#define THREEFISH_TWEAK (128 / 8) // 128-bit tweak

bool Threefish_KeySizeCheck(size_t keySize);

bool Threefish_KeySchedule(void* rawKey, size_t len, void* tweak, void* key);

void Threefish_Permutation(void* block, void* key);

void Threefish_Inverse(void* block, void* key);

void Threefish_SetPrimitive(CIPHER_PRIMITIVE** primitive);

#endif