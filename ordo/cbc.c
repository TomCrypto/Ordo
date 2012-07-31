/**
 * @file cbc.c
 * Implements the CBC mode of operation. The CBC mode is a block mode of operation, meaning that it performs
 * padding. It works by taking each block and XORing it with the IV. That ciphertext block then becomes the
 * IV for the next block to encrypt. Decryption is done by inverting this process. The padding algorithm is
 * PKCS7 (RFC 5652), which appends N bytes of value N, where N is the number of padding bytes required
 * (between 1 and the cipher's block size in bytes).
 *
 * @see cbc.h
 */

#include "primitives.h"
#include "encrypt.h"
#include "cbc.h"

/*! This is extra context space required by the CBC mode to store temporary incomplete data buffers.*/
typedef struct RESERVED
{
	/*! The temporary block, the size of the primitive's block size. */
	unsigned char* block;
	/*! The amount of bytes of plaintext or ciphertext currently in the temporary block. */
	size_t available;
} RESERVED;

/*! This structure describes a symmetric encryption context for the CBC mode. */
typedef struct CBC_ENCRYPT_CONTEXT
{
	/*! The primitive to use. */
	CIPHER_PRIMITIVE* primitive;
	/*! The mode of operation to use (this is set to the CBC mode). */
	struct ENCRYPT_MODE* mode;
	/*! Points to the key material. */
	void* key;
	/*! Unused field (CBC uses no initialization vector). */
	void* iv;
	/*! Whether to encrypt or decrypt (true = encryption). */
	int direction;
	/*! Whether padding is enabled or not. */
	int padding;
	/*! Reserved space for the CBC mode of operation. */
	RESERVED* reserved;
} CBC_ENCRYPT_CONTEXT;

void CBC_Create(ENCRYPT_CONTEXT* context)
{
    CBC_ENCRYPT_CONTEXT* ctx = (CBC_ENCRYPT_CONTEXT*)context;

	/* Allocate context fields. */
	ctx->key = salloc(ctx->primitive->szKey);
	ctx->iv = salloc(ctx->primitive->szBlock);
	ctx->reserved = salloc(sizeof(RESERVED));
	ctx->reserved->block = salloc(ctx->primitive->szBlock);
	ctx->reserved->available = 0;
}

/*! Initializes an CBC context (the primitive and mode must have been filled in).
  \param context The initialized encryption context.
  \param key A pointer to the key to use for encryption.
  \param keySize The size, in bytes, of the key.
  \param tweak The tweak to use (this may be zero, depending on the primitive).
  \param iv A pointer to the IV to use for encryption.
  \return Returns 0 on success, and a negative value on failure. Possible errors are:
  ORDO_EKEYSIZE: the key size is not valid for the context's primitive. */
int CBC_Init(ENCRYPT_CONTEXT* context, void* key, size_t keySize, void* tweak, void* iv)
{
    CBC_ENCRYPT_CONTEXT* ctx = (CBC_ENCRYPT_CONTEXT*)context;

	/* Check the key size. */
	if (!ctx->primitive->fKeyCheck(keySize)) return ORDO_EKEYSIZE;

    /* Copy the IV (required) into the context IV. */
	memcpy(ctx->iv, iv, ctx->primitive->szBlock);

	/* Perform the key schedule. */
	ctx->primitive->fKeySchedule(key, keySize, tweak, ctx->key);

	/* Return success. */
	return 0;
}

/*! Encrypts a buffer in CBC mode. The context must have been allocated and initialized.
  \param context The initialized encryption context.
  \param in A pointer to the plaintext buffer.
  \param inlen The size of the plaintext buffer, in bytes.
  \param out A pointer to the ciphertext buffer.
  \param outlen A pointer to an integer which will contain the amount of ciphertext output, in bytes.
  \return Returns true on success, false on failure.
  \remark The out buffer must have enough space to accomodate up to one more block size of ciphertext than plaintext, rounded down to the nearest block. */
void CBC_EncryptUpdate(ENCRYPT_CONTEXT* context, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
    CBC_ENCRYPT_CONTEXT* ctx = (CBC_ENCRYPT_CONTEXT*)context;

	/* Initialize output size. */
	*outlen = 0;

	/* Process all full blocks. */
	while (ctx->reserved->available + inlen >= ctx->primitive->szBlock)
	{
		/* Copy it in, and process it. */
		memcpy(ctx->reserved->block + ctx->reserved->available, in, ctx->primitive->szBlock - ctx->reserved->available);

		/* Exclusive-or the plaintext block with the running IV. */
        XOR(ctx->reserved->block, ctx->iv, ctx->primitive->szBlock);

		/* Encrypt the block. */
		ctx->primitive->fForward(ctx->reserved->block, ctx->key);

		/* Set this as the new running IV. */
		memcpy(ctx->iv, ctx->reserved->block, ctx->primitive->szBlock);

		/* Write back the block to the output. */
		memcpy(out, ctx->reserved->block, ctx->primitive->szBlock);
		*outlen += ctx->primitive->szBlock;
		out += ctx->primitive->szBlock;

		/* Go forward in the input buffer. */
		inlen -= ctx->primitive->szBlock - ctx->reserved->available;
		in += ctx->primitive->szBlock - ctx->reserved->available;
		ctx->reserved->available = 0;
	}

	/* Add whatever is left in the temporary buffer. */
	memcpy(ctx->reserved->block + ctx->reserved->available, in, inlen);
	ctx->reserved->available += inlen;
}

/*! Decrypts a buffer in CBC mode. The context must have been allocated and initialized.
  \param context The initialized encryption context.
  \param in A pointer to the ciphertext buffer.
  \param inlen The size of the ciphertext buffer, in bytes.
  \param out A pointer to the plaintext buffer.
  \param outlen A pointer to an integer which will contain the amount of plaintext output, in bytes.
  \remark The out buffer must have enough space to accomodate up to one more block size of plaintext than ciphertext, rounded down to the nearest block. */
void CBC_DecryptUpdate(ENCRYPT_CONTEXT* context, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
    CBC_ENCRYPT_CONTEXT* ctx = (CBC_ENCRYPT_CONTEXT*)context;

	/* Initialize output size. */
	*outlen = 0;

	/* Process all full blocks except the last potential block (if padding is disabled, also process the last block). */
	while (ctx->reserved->available + inlen > ctx->primitive->szBlock - (1 - ctx->padding))
	{
		/* Copy it in, and process it. */
		memcpy(ctx->reserved->block + ctx->reserved->available, in, ctx->primitive->szBlock - ctx->reserved->available);

        /* Save this ciphertext block. */
        memcpy(out, ctx->reserved->block, ctx->primitive->szBlock);

		/* Decrypt the block. */
		ctx->primitive->fInverse(ctx->reserved->block, ctx->key);

		/* Exclusive-or the block with the running IV. */
		XOR(ctx->reserved->block, ctx->iv, ctx->primitive->szBlock);

		/* Get the original ciphertext back as running IV. */
		memcpy(ctx->iv, out, ctx->primitive->szBlock);

		/* Write back the block to the output. */
		memcpy(out, ctx->reserved->block, ctx->primitive->szBlock);
		*outlen += ctx->primitive->szBlock;
		out += ctx->primitive->szBlock;

		/* Go forward in the input buffer. */
		inlen -= ctx->primitive->szBlock - ctx->reserved->available;
		in += ctx->primitive->szBlock - ctx->reserved->available;
		ctx->reserved->available = 0;
	}

	/* Save the final block. */
	memcpy(ctx->reserved->block + ctx->reserved->available, in, inlen);
	ctx->reserved->available += inlen;
}

/*! Finalizes an encryption context in CBC mode. The context must have been allocated and initialized.
  \param context The initialized encryption context.
  \param out A pointer to the final plaintext/ciphertext buffer.
  \param outlen A pointer to an integer which will contain the amount of plaintext output, in bytes.
  \return Returns true on success, false on failure.
  \remark The out buffer must have enough space to accomodate up to one block size of plaintext for padding. */
int CBC_EncryptFinal(ENCRYPT_CONTEXT* context, unsigned char* out, size_t* outlen)
{
    CBC_ENCRYPT_CONTEXT* ctx = (CBC_ENCRYPT_CONTEXT*)context;

	unsigned char padding;

	/* If padding is disabled, we need to handle things differently. */
	if (ctx->padding == 0)
	{
		/* If there is data left, return an error. */
		if (ctx->reserved->available != 0) return ORDO_EINVALID;

		/* Otherwise, just set the output size to zero. */
		if (outlen != 0) *outlen = 0;
	}
	else
    {
        /* Compute the amount of padding required. */
        padding = ctx->primitive->szBlock - ctx->reserved->available % ctx->primitive->szBlock;

        /* Write padding to the last block. */
        memset(ctx->reserved->block + ctx->reserved->available, padding, padding);

        /* Exclusive-or the last block with the running IV. */
        XOR(ctx->reserved->block, ctx->iv, ctx->primitive->szBlock);

        /* Encrypt the last block. */
        ctx->primitive->fForward(ctx->reserved->block, ctx->key);

        /* Write it out to the buffer. */
        memcpy(out, ctx->reserved->block, ctx->primitive->szBlock);
        *outlen = ctx->primitive->szBlock;
    }

	/* Return success. */
	return 0;
}

int CBC_DecryptFinal(ENCRYPT_CONTEXT* context, unsigned char* out, size_t* outlen)
{
    CBC_ENCRYPT_CONTEXT* ctx = (CBC_ENCRYPT_CONTEXT*)context;

	unsigned char padding;

	/* If padding is disabled, we need to handle things differently. */
	if (!ctx->padding)
	{
		/* If there is data left, return an error. */
		if (ctx->reserved->available != 0) return ORDO_EINVALID;

		/* Otherwise, just set the output size to zero. */
		if (outlen != 0) *outlen = 0;
	}
	else
    {
        /* Otherwise, decrypt the last block. */
        ctx->primitive->fInverse(ctx->reserved->block, ctx->key);

        /* Exclusive-or the last block with the running IV. */
        XOR(ctx->reserved->block, ctx->iv, ctx->primitive->szBlock);

        /* Read the amount of padding. */
        padding = *(ctx->reserved->block + ctx->primitive->szBlock - 1);

        /* Check the padding. */
        if ((padding != 0) && (padding <= ctx->primitive->szBlock) && (padcheck(ctx->reserved->block + ctx->primitive->szBlock - padding, padding)))
        {
            *outlen = ctx->primitive->szBlock - padding;
            memcpy(out, ctx->reserved->block, *outlen);
        } else return ORDO_EPADDING;
    }

	/* Return success. */
	return 0;
}

void CBC_Free(ENCRYPT_CONTEXT* context)
{
    CBC_ENCRYPT_CONTEXT* ctx = (CBC_ENCRYPT_CONTEXT*)context;

	/* Allocate context fields. */
	sfree(ctx->reserved->block, ctx->primitive->szBlock);
	sfree(ctx->reserved, sizeof(RESERVED));
	sfree(ctx->iv, ctx->primitive->szBlock);
	sfree(ctx->key, ctx->primitive->szKey);
}

/* Fills a ENCRYPT_MODE struct with the correct information. */
void CBC_SetMode(ENCRYPT_MODE** mode)
{
	(*mode) = malloc(sizeof(ENCRYPT_MODE));
	(*mode)->fCreate = &CBC_Create;
	(*mode)->fInit = &CBC_Init;
	(*mode)->fEncryptUpdate = &CBC_EncryptUpdate;
	(*mode)->fDecryptUpdate = &CBC_DecryptUpdate;
	(*mode)->fEncryptFinal = &CBC_EncryptFinal;
	(*mode)->fDecryptFinal = &CBC_DecryptFinal;
	(*mode)->fFree = &CBC_Free;
	(*mode)->name = "CBC";
}
