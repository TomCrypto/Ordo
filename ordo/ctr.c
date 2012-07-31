/**
 * @file ctr.c
 * Implements the CTR mode of operation. CTR is a streaming mode of operation, which performs no padding and works by
 * feeding an ever-increasing counter (initially set to the initialization vector) into the cipher's permutation to
 * produce the keystream, which is subsequently exclusive-or'ed bitwise with the plaintext to produce the ciphertext.
 * As such, CTR decryption is identical to CTR encryption, and the cipher's inverse permutation function is not used.
 *
 * @see ctr.h
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
	int direction;
	/*! Whether padding is enabled or not. */
	int padding;
	/*! Reserved space for the CTR mode of operation. */
	RESERVED* reserved;
} CTR_ENCRYPT_CONTEXT;

/* Increments a counter of arbitrary size as if it were a len-byte integer
   Propagation is done from left-to-right in memory storage order. */
void incCounter(unsigned char* iv, size_t len)
{
	/* Increment the first byte. */
	size_t t;
	int carry = (++*iv == 0);

	/* Go over each byte, and propagate the carry. */
	for (t = 1; t < len; t++)
	{
		if (carry == 1) carry = (++*(iv + t) == 0);
		else break;
	}
}

void CTR_Create(ENCRYPT_CONTEXT* context)
{
    CTR_ENCRYPT_CONTEXT* ctx = (CTR_ENCRYPT_CONTEXT*)context;

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
int CTR_Init(ENCRYPT_CONTEXT* context, void* key, size_t keySize, void* tweak, void* iv)
{
    CTR_ENCRYPT_CONTEXT* ctx = (CTR_ENCRYPT_CONTEXT*)context;

	/* Check the key size. */
	if (!ctx->primitive->fKeyCheck(keySize)) return ORDO_EKEYSIZE;

	/* Copy the IV (required) into the context IV. */
	memcpy(ctx->iv, iv, ctx->primitive->szBlock);

	/* Perform the key schedule. */
	ctx->primitive->fKeySchedule(key, keySize, tweak, ctx->key);

	/* Copy the IV into the counter. */
	memcpy(ctx->reserved->counter, ctx->iv, ctx->primitive->szBlock);

	/* Compute the initial keystream block. */
	ctx->primitive->fForward(ctx->iv, ctx->key);
	ctx->reserved->remaining = ctx->primitive->szBlock;

	/* Return success. */
	return 0;
}

/*! Encrypts/decrypts a buffer in CTR mode. The context must have been allocated and initialized.
  \param ctx The initialized encryption context.
  \param in A pointer to the plaintext buffer.
  \param inlen The size of the plaintext buffer, in bytes.
  \param out A pointer to the ciphertext buffer.
  \param outlen A pointer to an integer which will contain the amount of ciphertext output, in bytes.
  \remark The out buffer must be the same size as the in buffer, as CTR is a streaming mode. */
void CTR_Update(ENCRYPT_CONTEXT* context, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
    CTR_ENCRYPT_CONTEXT* ctx = (CTR_ENCRYPT_CONTEXT*)context;

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
}

/*! Finalizes an encryption context in CTR mode. The context must have been allocated and initialized.
  \param ctx The initialized encryption context.
  \param out Set this to zero as the CTR mode uses no padding.
  \param outlen Set this to null.
  \param decrypt Unused parameter.
  \return Returns true on success, false on failure. */
int CTR_Final(ENCRYPT_CONTEXT* context, unsigned char* out, size_t* outlen)
{
    CTR_ENCRYPT_CONTEXT* ctx = (CTR_ENCRYPT_CONTEXT*)context;

	/* Write output size if applicable. */
	if (outlen != 0) *outlen = 0;

	/* Return success. */
	return 0;
}

void CTR_Free(ENCRYPT_CONTEXT* context)
{
    CTR_ENCRYPT_CONTEXT* ctx = (CTR_ENCRYPT_CONTEXT*)context;

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
	(*mode)->fEncryptUpdate = &CTR_Update;
	(*mode)->fDecryptUpdate = &CTR_Update;
	(*mode)->fEncryptFinal = &CTR_Final;
	(*mode)->fDecryptFinal = &CTR_Final;
	(*mode)->fFree = &CTR_Free;
	(*mode)->name = "CTR";
}
