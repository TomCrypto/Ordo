#ifndef ctr_h
#define ctr_h

void CTR_Init(CIPHER_CONTEXT* ctx, void* key, void* tweak, void* iv);

void CTR_Encrypt(CIPHER_CONTEXT* ctx, unsigned char* buffer, size_t* size, bool final);

void CTR_Decrypt(CIPHER_CONTEXT* ctx, unsigned char* buffer, size_t* size, bool final);

void CTR_Final(CIPHER_CONTEXT* ctx);

void CTR_SetMode(CIPHER_MODE** mode);

#endif