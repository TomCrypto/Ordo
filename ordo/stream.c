/**
 * @file STREAM.c
 * Implements the STREAM mode of operation. STREAM is a streaming mode of operation which is only compatible with
 * stream ciphers (such as RC4). It uses no initialization vector, and does not use padding.
 *
 * @see STREAM.h
 */

#include "primitives.h"
#include "encrypt.h"
#include "stream.h"

/*! This is extra context space required by the STREAM mode to store the counter and the amount of state not used.*/
typedef struct RESERVED
{
	/*! The amount of bytes of unused state remaining before the state is to be renewed. */
	size_t remaining;
} RESERVED;

/*! This structure describes a symmetric encryption context for the STREAM mode. */
typedef struct STREAM_ENCRYPT_CONTEXT
{
	/*! The primitive to use. */
	CIPHER_PRIMITIVE* primitive;
	/*! The mode of operation to use (this is set to the STREAM mode). */
	struct ENCRYPT_MODE* mode;
	/*! Points to the key material. */
	void* key;
	/*! Points to the initialization vector. */
	void* iv;
	/*! Whether to encrypt or decrypt (true = encryption). */
	bool direction;
	/*! Whether padding is enabled or not. */
	bool padding;
	/*! Unused space. */
	RESERVED* reserved;
} STREAM_ENCRYPT_CONTEXT;

void STREAM_Create(STREAM_ENCRYPT_CONTEXT* ctx)
{
	/* Allocate context space. */
	ctx->key = salloc(ctx->primitive->szKey);
	ctx->iv = salloc(ctx->primitive->szBlock);
	ctx->reserved = salloc(sizeof(RESERVED));
}

/*! Initializes a STREAM context (the primitive and mode must have been filled in).
  \param ctx The initialized encryption context.
  \param key A pointer to the key to use for encryption.
  \param keySize The size, in bytes, of the key.
  \param tweak The tweak to use (this may be zero, depending on the primitive).
  \param iv The initialization vector to use.
  \return Returns true on success, false on failure. */
bool STREAM_Init(STREAM_ENCRYPT_CONTEXT* ctx, void* key, size_t keySize, void* tweak, void* iv)
{
	/* Check the key size. */
	if (!ctx->primitive->fKeyCheck(keySize)) return false;

	/* Perform the key schedule. */
	if (!ctx->primitive->fKeySchedule(key, keySize, tweak, ctx->key)) return false;

	/* Compute the initial keystream block. */
	ctx->primitive->fForward(ctx->iv, ctx->key);
	ctx->reserved->remaining = ctx->primitive->szBlock;

	/* Return success. */
	return true;
}

/*! Encrypts a buffer in STREAM mode. The context must have been allocated and initialized.
  \param ctx The initialized encryption context.
  \param in A pointer to the plaintext buffer.
  \param inlen The size of the plaintext buffer, in bytes.
  \param out A pointer to the ciphertext buffer.
  \param outlen A pointer to an integer which will contain the amount of ciphertext output, in bytes.
  \return Returns true on success, false on failure.
  \remark The out buffer must be the same size as the in buffer, as STREAM is a streaming mode. */
bool STREAM_EncryptUpdate(STREAM_ENCRYPT_CONTEXT* ctx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
	/* Initialize the output size. */
	*outlen = 0;

	/* Go over the input buffer byte per byte. */
	while (inlen != 0)
	{
		/* If there is no data left in the context block, update. */
		if (ctx->reserved->remaining == 0)
		{
			/* STREAM update (simply renew the state). */
			ctx->primitive->fForward(ctx->iv, ctx->key);
			ctx->reserved->remaining = ctx->primitive->szBlock;
		}

		/* Encrypt this plaintext byte. */
		*out = *in ^ *((unsigned char*)ctx->iv + ctx->primitive->szBlock - ctx->reserved->remaining);

		/* Go to the next byte. */
		ctx->reserved->remaining--;
		in++;
		out++;
		inlen--;
		(*outlen)++;
	}

	/* Return success. */
	return true;
}

/*! Decrypts a buffer in STREAM mode. The context must have been allocated and initialized.
  \param ctx The initialized encryption context.
  \param in A pointer to the ciphertext buffer.
  \param inlen The size of the ciphertext buffer, in bytes.
  \param out A pointer to the plaintext buffer.
  \param outlen A pointer to an integer which will contain the amount of plaintext output, in bytes.
  \return Returns true on success, false on failure.
  \remark The out buffer must be the same size as the in buffer, as STREAM is a streaming mode.  */
bool STREAM_DecryptUpdate(STREAM_ENCRYPT_CONTEXT* ctx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
	/* STREAM encryption and decryption are equivalent. */
	return STREAM_EncryptUpdate(ctx, in, inlen, out, outlen);
}

/*! Finalizes an encryption context in STREAM mode. The context must have been allocated and initialized.
  \param ctx The initialized encryption context.
  \param out Set this to zero as the STREAM mode uses no padding.
  \param outlen Set this to null.
  \param decrypt Unused parameter.
  \return Returns true on success, false on failure. */
bool STREAM_Final(STREAM_ENCRYPT_CONTEXT* ctx, unsigned char* out, size_t* outlen)
{
	/* Write output size if applicable. */
	if (outlen != 0) *outlen = 0;

	/* Return success. */
	return true;
}

void STREAM_Free(STREAM_ENCRYPT_CONTEXT* ctx)
{
	/* Free context space. */
	sfree(ctx->reserved, sizeof(RESERVED));
	sfree(ctx->iv, ctx->primitive->szBlock);
	sfree(ctx->key, ctx->primitive->szKey);
}

/* Fills a ENCRYPT_MODE struct with the correct information. */
void STREAM_SetMode(ENCRYPT_MODE** mode)
{
	(*mode) = malloc(sizeof(ENCRYPT_MODE));
	(*mode)->fCreate = &STREAM_Create;
	(*mode)->fInit = &STREAM_Init;
	(*mode)->fEncryptUpdate = &STREAM_EncryptUpdate;
	(*mode)->fDecryptUpdate = &STREAM_DecryptUpdate;
	(*mode)->fEncryptFinal = &STREAM_Final;
	(*mode)->fDecryptFinal = &STREAM_Final;
	(*mode)->fFree = &STREAM_Free;
	(*mode)->name = "STREAM";
}