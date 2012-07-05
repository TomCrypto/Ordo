#ifndef ofb_h
#define ofb_h

bool OFB_Init(ENCRYPT_CONTEXT* ctx, void* key, size_t keySize, void* tweak, void* iv);

bool OFB_Encrypt(ENCRYPT_CONTEXT* ctx, unsigned char* buffer, size_t* size, bool final);

bool OFB_Decrypt(ENCRYPT_CONTEXT* ctx, unsigned char* buffer, size_t* size, bool final);

void OFB_Final(ENCRYPT_CONTEXT* ctx);

void OFB_SetMode(ENCRYPT_MODE** mode);

#endif