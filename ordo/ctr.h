#ifndef ctr_h
#define ctr_h

bool CTR_Init(ENCRYPT_CONTEXT* ctx, void* key, size_t keySize, void* tweak, void* iv);

bool CTR_Encrypt(ENCRYPT_CONTEXT* ctx, unsigned char* buffer, size_t* size, bool final);

bool CTR_Decrypt(ENCRYPT_CONTEXT* ctx, unsigned char* buffer, size_t* size, bool final);

void CTR_Final(ENCRYPT_CONTEXT* ctx);

void CTR_SetMode(ENCRYPT_MODE** mode);

#endif