#ifndef ofb_h
#define ofb_h

bool OFB_Init(CIPHER_CONTEXT* ctx, void* key, size_t keySize, void* tweak, void* iv);

bool OFB_Encrypt(CIPHER_CONTEXT* ctx, unsigned char* buffer, size_t* size, bool final);

bool OFB_Decrypt(CIPHER_CONTEXT* ctx, unsigned char* buffer, size_t* size, bool final);

void OFB_Final(CIPHER_CONTEXT* ctx);

void OFB_SetMode(CIPHER_MODE** mode);

#endif