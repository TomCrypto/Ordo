#ifndef ecb_h
#define ecb_h

bool ECB_Init(CIPHER_CONTEXT* ctx, void* key, size_t keySize, void* tweak, void* iv);

bool ECB_Encrypt(CIPHER_CONTEXT* ctx, unsigned char* buffer, size_t* size, bool final);

bool ECB_Decrypt(CIPHER_CONTEXT* ctx, unsigned char* buffer, size_t* size, bool final);

void ECB_Final(CIPHER_CONTEXT* ctx);

void ECB_SetMode(CIPHER_MODE** mode);

#endif