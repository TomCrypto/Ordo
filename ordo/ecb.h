#ifndef ecb_h
#define ecb_h

void ECB_Init(CIPHER_CONTEXT* ctx, void* key, void* tweak, void* iv);

void ECB_Encrypt(CIPHER_CONTEXT* ctx, char* buffer, size_t* size, size_t padding);

void ECB_Decrypt(CIPHER_CONTEXT* ctx, char* buffer, size_t* size, size_t padding);

void ECB_Final(CIPHER_CONTEXT* ctx);

void ECB_SetMode(CIPHER_MODE* mode);

#endif