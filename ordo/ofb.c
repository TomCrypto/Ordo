/**
 * @file OFB.c
 * Implements the OFB mode of operation. OFB is a streaming mode of operation which performs no padding and works
 * by iterating the cipher primitive's permutation function on the initialization vector to produce the keystream
 * which is subsequently exclusive-or'ed bitwise with the plaintext to produce the ciphertext. As such, OFB
 * decryption is identical to encryption, and the cipher's inverse permutation function is not used.
 *
 * @see OFB.h
 */

#include "primitives.h"
#include "encrypt.h"
#include "ofb.h"

/*! This is extra context space required by the OFB mode to store the amount of state not used.*/
typedef struct RESERVED
{
	/*! The amount of bytes of unused state remaining before the state is to be renewed. */
	size_t remaining;
} RESERVED;

/*! This structure describes a symmetric encryption context for the OFB mode. */
typedef struct OFB_ENCRYPT_CONTEXT
{
	/*! The primitive to use. */
	CIPHER_PRIMITIVE* primitive;
	/*! The mode of operation to use (this is set to the OFB mode). */
	struct ENCRYPT_MODE* mode;
	/*! Points to the key material. */
	void* key;
	/*! Points to the initialization vector. */
	void* iv;
	/*! Whether to encrypt or decrypt (true = encryption). */
	int direction;
	/*! Whether padding is enabled or not. */
	int padding;
	/*! Reserved space for the OFB mode of operation. */
	RESERVED* reserved;
} OFB_ENCRYPT_CONTEXT;

void OFB_Create(ENCRYPT_CONTEXT* context)
{
    OFB_ENCRYPT_CONTEXT* ctx = (OFB_ENCRYPT_CONTEXT*)context;

	/* Allocate context space. */
	ctx->key = salloc(ctx->primitive->szKey);
	ctx->iv = salloc(ctx->primitive->szBlock);
	ctx->reserved = salloc(sizeof(RESERVED));
}

/*! Initializes an OFB context (the primitive and mode must have been filled in).
  \param ctx The initialized encryption context.
  \param key A pointer to the key to use for encryption.
  \param keySize The size, in bytes, of the key.
  \param tweak The tweak to use (this may be zero, depending on the primitive).
  \param iv The initialization vector to use.
  \return Returns true on success, false on failure. */
int OFB_Init(ENCRYPT_CONTEXT* context, void* key, size_t keySize, void* tweak, void* iv)
{
    OFB_ENCRYPT_CONTEXT* ctx = (OFB_ENCRYPT_CONTEXT*)context;

	/* Check the key size. */
	if (!ctx->primitive->fKeyCheck(keySize)) return ORDO_EKEYSIZE;

	/* Copy the IV (required) into the context IV. */
	memcpy(ctx->iv, iv, ctx->primitive->szBlock);

	/* Perform the key schedule. */
	ctx->primitive->fKeySchedule(key, keySize, tweak, ctx->key);

	/* Compute the initial keystream block. */
	ctx->primitive->fForward(ctx->iv, ctx->key);
	ctx->reserved->remaining = ctx->primitive->szBlock;

	/* Return success. */
	return 0;
}

/*! Encrypts/decrypts a buffer in OFB mode. The context must have been allocated and initialized.
  \param ctx The initialized encryption context.
  \param in A pointer to the plaintext buffer.
  \param inlen The size of the plaintext buffer, in bytes.
  \param out A pointer to the ciphertext buffer.
  \param outlen A pointer to an integer which will contain the amount of ciphertext output, in bytes.
  \return Returns true on success, false on failure.
  \remark The out buffer must be the same size as the in buffer, as OFB is a streaming mode. */
void OFB_Update(ENCRYPT_CONTEXT* context, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
    OFB_ENCRYPT_CONTEXT* ctx = (OFB_ENCRYPT_CONTEXT*)context;

	/* Initialize the output size. */
	*outlen = 0;

	/* Go over the buffer byte per byte. */
	while (inlen != 0)
	{
		/* If there is no data left in the context block, update. */
		if (ctx->reserved->remaining == 0)
		{
			/* OFB update (simply apply the permutation function again). */
			ctx->primitive->fForward(ctx->iv, ctx->key);
			ctx->reserved->remaining = ctx->primitive->szBlock;
		}

		/* Encrypt this plaintext byte. */
		*out = *in ^ *((unsigned char*)ctx->iv + ctx->primitive->szBlock - ctx->reserved->remaining);

		ctx->reserved->remaining--;
		in++;
		out++;
		inlen--;
		(*outlen)++;
	}
}

/*! Finalizes an encryption context in OFB mode. The context must have been allocated and initialized.
  \param ctx The initialized encryption context.
  \param out Set this to zero as the OFB mode uses no padding.
  \param outlen Set this to null.
  \param decrypt Unused parameter.
  \return Returns true on success, false on failure. */
int OFB_Final(ENCRYPT_CONTEXT* context, unsigned char* out, size_t* outlen)
{
    OFB_ENCRYPT_CONTEXT* ctx = (OFB_ENCRYPT_CONTEXT*)context;

	/* Write output size if applicable. */
	if (outlen != 0) *outlen = 0;

	/* Return success. */
	return 0;
}

void OFB_Free(ENCRYPT_CONTEXT* context)
{
    OFB_ENCRYPT_CONTEXT* ctx = (OFB_ENCRYPT_CONTEXT*)context;

	/* Free context space. */
	sfree(ctx->reserved, sizeof(RESERVED));
	sfree(ctx->iv, ctx->primitive->szBlock);
	sfree(ctx->key, ctx->primitive->szKey);
}

/* Fills a ENCRYPT_MODE struct with the correct information. */
void OFB_SetMode(ENCRYPT_MODE** mode)
{
	(*mode) = malloc(sizeof(ENCRYPT_MODE));
	(*mode)->fCreate = &OFB_Create;
	(*mode)->fInit = &OFB_Init;
	(*mode)->fEncryptUpdate = &OFB_Update;
	(*mode)->fDecryptUpdate = &OFB_Update;
	(*mode)->fEncryptFinal = &OFB_Final;
	(*mode)->fDecryptFinal = &OFB_Final;
	(*mode)->fFree = &OFB_Free;
	(*mode)->name = "OFB";
}
