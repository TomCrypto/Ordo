#ifndef cipher_h
#define cipher_h

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "secmem.h"

/* Prototype for a key schedule function, taking as an input a key and a tweak. */
typedef void (* KEYSCHEDULE)(void*, void*, void*);

/* Prototype for a permutation function, taking as an input a block and key. */
typedef void (* PERMUTATION)(void*, void*);

/* This structure defines a symmetric cipher primitive. */
typedef struct CIPHER_PRIMITIVE
{
	size_t szRawKey; // raw key size (before key schedule), in bytes
	size_t szKey; // key size (after key schedule), in bytes
	size_t szBlock; // block size, in bytes
	size_t szTweak; // tweak size, in bytes (can be zero)
	PERMUTATION fPermutation; // points to the cipher's permutation function
	PERMUTATION fInverse; // points to the cipher's inverse permutation function
	KEYSCHEDULE fKeySchedule; // points to the cipher's key schedule function
	char* name; // the cipher's name
} CIPHER_PRIMITIVE;

/* This structure describes a symmetric cipher context. */
typedef struct CIPHER_CONTEXT
{
	struct CIPHER_PRIMITIVE *primitive; // the primitive in use
	struct CIPHER_MODE *mode; // the mode of operation in use
	void* key; // location of the key
	void* iv; // location of the IV (may be null)
	void* block; // scratch space to store the current block
	size_t blockSize; // currently used block size
} CIPHER_CONTEXT;

/* Prototype for a mode of operation, taking as an input a buffer, buffer size, and context. */
typedef void (* INI_OP)(struct CIPHER_CONTEXT*, void*, void*, void*);
typedef void (* ENC_OP)(struct CIPHER_CONTEXT*, char*, size_t*, size_t);
typedef void (* FIN_OP)(struct CIPHER_CONTEXT*);

/* This structure defines a mode of operation. */
typedef struct CIPHER_MODE
{
	INI_OP fInit; // points to the mode of operation's initialization function
	ENC_OP fEncrypt; // points to the mode of operation's encryption function
	ENC_OP fDecrypt; // points to the mode of operation's decryption function
	FIN_OP fFinal; // points to the mode of operation's finalization function
	char* name; // the mode of operation's name
} CIPHER_MODE;

/* Cipher list. */
#include "identity.h"
CIPHER_PRIMITIVE IDENTITY;
#include "xortoy.h"
CIPHER_PRIMITIVE XORTOY;
#include "threefish.h"
CIPHER_PRIMITIVE THREEFISH;

/* Mode of operation list. */
#include "ecb.h"
CIPHER_MODE ECB;
#include "ctr.h"
CIPHER_MODE CTR;

void loadPrimitives();
void loadModes();

/* This function encrypts a buffer with a given key and IV. */
size_t cipherEncrypt(char* buffer, size_t* size, CIPHER_PRIMITIVE primitive, CIPHER_MODE mode, void* key, void* tweak, void* iv);

/* This function decrypts a buffer with a given key and IV. */
size_t cipherDecrypt(char* buffer, size_t* size, CIPHER_PRIMITIVE primitive, CIPHER_MODE mode, void* key, void* tweak, void* iv);

#endif