/**
 * @file CTR.c
 * Implements the CTR mode of operation. CTR is a streaming mode of operation, which performs no padding and works by
 * feeding an ever-increasing counter (initially set to the initialization vector) into the cipher's permutation to
 * produce the keystream, which is subsequently exclusive-or'ed bitwise with the plaintext to produce the ciphertext.
 * As such, CTR decryption is identical to CTR encryption, and the cipher's inverse permutation function is not used.
 *
 * @see CTR.h
 */

#include "primitives.h"
#include "encrypt.h"
#include "ctr.h"

/*! This is extra context space required by the CTR mode to store the counter and the amount of state not used.*/
typedef struct RESERVED
{
	/*! The counter value. */
	unsigned char* counter;
	/*! The amount of bytes of unused state remaining before the state is to be renewed. */
	size_t remaining;
} RESERVED;

/*! This structure describes a symmetric encryption context for the CTR mode. */
typedef struct CTR_ENCRYPT_CONTEXT
{
	/*! The primitive to use. */
	CIPHER_PRIMITIVE* primitive;
	/*! The mode of operation to use (this is set to the CTR mode). */
	struct ENCRYPT_MODE* mode;
	/*! Points to the key material. */
	void* key;
	/*! Points to the initialization vector. */
	void* iv;
	/*! Whether to encrypt or decrypt (true = encryption). */
	bool direction;
	/*! Whether padding is enabled or not. */
	bool padding;
	/*! Reserved space for the CTR mode of operation. */
	RESERVED* reserved;
} CTR_ENCRYPT_CONTEXT;

/* Increments a counter of arbitrary size as if it were a len-byte integer
   Propagation is done from left-to-right in memory storage order. */
void incCounter(unsigned char* iv, size_t len)
{
	/* Increment the first byte. */
	size_t t;
	bool carry = (++*iv == 0);

	/* Go over each byte, and propagate the carry. */
	for (t = 1; t < len; t++)
	{
		if (carry) carry = (++*(iv + t) == 0);
		else break;
	}
}

void CTR_Create(CTR_ENCRYPT_CONTEXT* ctx)
{
	/* Allocate context space. */
	ctx->key = salloc(ctx->primitive->szKey);
	ctx->iv = salloc(ctx->primitive->szBlock);
	ctx->reserved = salloc(sizeof(RESERVED));
	ctx->reserved->counter = salloc(ctx->primitive->szBlock);
}

/*! Initializes a CTR context (the primitive and mode must have been filled in).
  \param ctx The initialized encryption context.
  \param key A pointer to the key to use for encryption.
  \param keySize The size, in bytes, of the key.
  \param tweak The tweak to use (this may be zero, depending on the primitive).
  \param iv The initialization vector to use.
  \return Returns true on success, false on failure. */
bool CTR_Init(CTR_ENCRYPT_CONTEXT* ctx, void* key, size_t keySize, void* tweak, void* iv)
{
	/* Check the key size. */
	if (!ctx->primitive->fKeyCheck(keySize)) return false;

	/* Copy the IV (required) into the context IV. */
	memcpy(ctx->iv, iv, ctx->primitive->szBlock); 

	/* Perform the key schedule. */
	if (!ctx->primitive->fKeySchedule(key, keySize, tweak, ctx->key)) return false;

	/* Copy the IV into the counter. */
	memcpy(ctx->reserved->counter, ctx->iv, ctx->primitive->szBlock);

	/* Compute the initial keystream block. */
	ctx->primitive->fPermutation(ctx->iv, ctx->key);
	ctx->reserved->remaining = ctx->primitive->szBlock;

	/* Return success. */
	return true;
}

/*! Encrypts a buffer in CTR mode. The context must have been allocated and initialized.
  \param ctx The initialized encryption context.
  \param in A pointer to the plaintext buffer.
  \param inlen The size of the plaintext buffer, in bytes.
  \param out A pointer to the ciphertext buffer.
  \param outlen A pointer to an integer which will contain the amount of ciphertext output, in bytes.
  \return Returns true on success, false on failure.
  \remark The out buffer must be the same size as the in buffer, as CTR is a streaming mode. */
bool CTR_EncryptUpdate(CTR_ENCRYPT_CONTEXT* ctx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
	/* Initialize the output size. */
	*outlen = 0;

	/* Go over the input buffer byte per byte. */
	while (inlen != 0)
	{
		/* If there is no data left in the context block, update. */
		if (ctx->reserved->remaining == 0)
		{
			/* CTR update (increment counter, copy counter into IV, encrypt IV). */
			incCounter(ctx->reserved->counter, ctx->primitive->szBlock);
			memcpy(ctx->iv, ctx->reserved->counter, ctx->primitive->szBlock);
			ctx->primitive->fPermutation(ctx->iv, ctx->key);
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

/*! Decrypts a buffer in CTR mode. The context must have been allocated and initialized.
  \param ctx The initialized encryption context.
  \param in A pointer to the ciphertext buffer.
  \param inlen The size of the ciphertext buffer, in bytes.
  \param out A pointer to the plaintext buffer.
  \param outlen A pointer to an integer which will contain the amount of plaintext output, in bytes.
  \return Returns true on success, false on failure.
  \remark The out buffer must be the same size as the in buffer, as CTR is a streaming mode.  */
bool CTR_DecryptUpdate(CTR_ENCRYPT_CONTEXT* ctx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
	/* CTR encryption and decryption are equivalent. */
	return CTR_EncryptUpdate(ctx, in, inlen, out, outlen);
}

/*! Finalizes an encryption context in CTR mode. The context must have been allocated and initialized.
  \param ctx The initialized encryption context.
  \param out Set this to zero as the CTR mode uses no padding.
  \param outlen Set this to null.
  \param decrypt Unused parameter.
  \return Returns true on success, false on failure. */
bool CTR_Final(CTR_ENCRYPT_CONTEXT* ctx, unsigned char* out, size_t* outlen)
{
	/* Write output size if applicable. */
	if (outlen != 0) *outlen = 0;

	/* Return success. */
	return true;
}

void CTR_Free(CTR_ENCRYPT_CONTEXT* ctx)
{
	/* Free context space. */
	sfree(ctx->reserved->counter, ctx->primitive->szBlock);
	sfree(ctx->reserved, sizeof(RESERVED));
	sfree(ctx->iv, ctx->primitive->szBlock);
	sfree(ctx->key, ctx->primitive->szKey);
}

/* Fills a ENCRYPT_MODE struct with the correct information. */
void CTR_SetMode(ENCRYPT_MODE** mode)
{
	(*mode) = malloc(sizeof(ENCRYPT_MODE));
	(*mode)->fCreate = &CTR_Create;
	(*mode)->fInit = &CTR_Init;
	(*mode)->fEncryptUpdate = &CTR_EncryptUpdate;
	(*mode)->fDecryptUpdate = &CTR_DecryptUpdate;
	(*mode)->fEncryptFinal = &CTR_Final;
	(*mode)->fDecryptFinal = &CTR_Final;
	(*mode)->fFree = &CTR_Free;
	(*mode)->name = "CTR";
}