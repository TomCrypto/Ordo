#ifndef ctr_h
#define ctr_h

bool CTR_Init(CIPHER_CONTEXT* ctx, void* key, size_t keySize, void* tweak, void* iv);

bool CTR_Encrypt(CIPHER_CONTEXT* ctx, unsigned char* buffer, size_t* size, bool final);

bool CTR_Decrypt(CIPHER_CONTEXT* ctx, unsigned char* buffer, size_t* size, bool final);

void CTR_Final(CIPHER_CONTEXT* ctx);

void CTR_SetMode(CIPHER_MODE** mode);

#endif