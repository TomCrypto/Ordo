// Ordo.cpp : Defines the entry posize_t for the console application.
//

#include <stdio.h>
#include "cipher.h"

/* Binary to hex. */
void hex(void* input, size_t len)
{
	size_t t;
	for (t = 0; t < len; t++) printf("%.2x", (unsigned char)*((char*)input + t));
}

void testPrimitiveMode(CIPHER_PRIMITIVE* primitive, CIPHER_MODE* mode, size_t size)
{
	/* Declare variables. */
	void* buffer;
	void* iv;
	void* key;
	size_t pad;

	/* Store the size and pad it up to the block size (this is only needed for ECB/CBC/etc... */
	size_t sz = size;
	if (size % primitive->szBlock == 0) pad = size + primitive->szBlock;
	else pad = size + primitive->szBlock - size % primitive->szBlock;

	/* Allocate a buffer and fill it with 0x77 bytes.*/
	buffer = malloc(pad);
	memset(buffer, 0x00, pad);
	memset(buffer, 0x77, size);

	/* Allocate a buffer of the right size (= cipher block size) and fill it with 0xAA. */
	iv = malloc(primitive->szBlock);
	memset(iv, 0xAA, primitive->szBlock);

	/* Allocate a key of the right sie, and fill it with 0xEE. */
	key = malloc(primitive->szRawKey);
	memset(key, 0xEE, primitive->szRawKey);

	/* Print data BEFORE encryption. */
	printf("Cipher: %s | Mode: %s\n", primitive->name, mode->name);
	printf("Plaintext  : ");
	hex(buffer, size);
	printf(" (%d bytes)\n", size);

	/* Encrypt. */
	cipherEncrypt((unsigned char*)buffer, &size, primitive, mode, key, 0, iv);

	/* Print data AFTER encryption. */
	printf("Ciphertext : ");
	hex(buffer, size);
	printf(" (%d bytes)\n", size);

	/* Decrypt. */
	cipherDecrypt((unsigned char*)buffer, &size, primitive, mode, key, 0, iv);

	/* Print data AFTER decryption. */
	printf("Plaintext  : ");
	hex(buffer, size);
	printf(" (%d bytes)\n", size);

	printf("\n---\n\n");

	free(key);
}

size_t main(size_t argc, char* argv[])
{
	printf("Loading all cipher primitives.\n");
	loadPrimitives();

	printf("Loading all cipher modes.\n");
	loadModes();

	printf("\n---\n\n");

	testPrimitiveMode(IDENTITY, ECB, 11);
	testPrimitiveMode(IDENTITY, CTR, 9);
	testPrimitiveMode(XORTOY, ECB, 19);
	testPrimitiveMode(XORTOY, CTR, 33);
	testPrimitiveMode(THREEFISH, ECB, 29);
	testPrimitiveMode(THREEFISH, CTR, 12);

	system("pause");
	return 0;
}