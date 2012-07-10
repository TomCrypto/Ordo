#ifndef ctr_h
#define ctr_h

void CTR_Create(ENCRYPT_CONTEXT* ctx);

bool CTR_Init(ENCRYPT_CONTEXT* ctx, void* key, size_t keySize, void* tweak, void* iv);

bool CTR_EncryptUpdate(ENCRYPT_CONTEXT* ctx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen);

bool CTR_DecryptUpdate(ENCRYPT_CONTEXT* ctx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen);

bool CTR_Final(ENCRYPT_CONTEXT* ctx, unsigned char* out, size_t* outlen);

void CTR_Free(ENCRYPT_CONTEXT* ctx);

void CTR_SetMode(ENCRYPT_MODE** mode);

#endif