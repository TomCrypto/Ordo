#ifndef ecb_h
#define ecb_h

bool ECB_Init(ENCRYPT_CONTEXT* ctx, void* key, size_t keySize, void* tweak, void* iv);

bool ECB_Encrypt(ENCRYPT_CONTEXT* ctx, unsigned char* buffer, size_t* size, bool final);

bool ECB_Decrypt(ENCRYPT_CONTEXT* ctx, unsigned char* buffer, size_t* size, bool final);

void ECB_Final(ENCRYPT_CONTEXT* ctx);

void ECB_SetMode(ENCRYPT_MODE** mode);

#endif