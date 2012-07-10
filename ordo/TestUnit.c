#include <stdio.h>
#include "ordo.h"

/* Binary to hex. */
void hex(void* input, size_t len)
{
	size_t t;
	for (t = 0; t < len; t++) printf("%.2x", (unsigned char)*((char*)input + t));
}

void testPrimitiveMode(CIPHER_PRIMITIVE* primitive, ENCRYPT_MODE* mode, size_t size, size_t keySize)
{
	/* Declare variables. */
	void* in;
	void* out;
	void* iv;
	void* key;
	size_t pad;

	/* Store the size and pad it up to the block size (this is only needed for ECB/CBC/etc... but it will be ignored for streaming modes, the extra space will simply be disregarded by the API) */
	size_t sz = size;
	if (size % primitive->szBlock == 0) pad = size + primitive->szBlock;
	else pad = size + primitive->szBlock - size % primitive->szBlock;

	/* Allocate a plaintext buffer and fill it with 0x77 bytes.*/
	in = malloc(size);
	memset(in, 0x77, size);

	/* Allocate a ciphertext buffer.*/
	out = malloc(pad);

	/* Allocate a buffer of the right size (= cipher block size) and fill it with 0xAA. */
	iv = malloc(primitive->szBlock);
	memset(iv, 0xAA, primitive->szBlock);

	/* Allocate a key of the right sie, and fill it with 0xEE. */
	key = malloc(keySize);
	memset(key, 0xEE, keySize);

	/* Print data BEFORE encryption. */
	printf("Cipher: %s | Mode: %s (key length = %d bits)\n", primitive->name, mode->name, keySize * 8);
	printf("Plaintext  : ");
	hex(in, size);
	printf(" (%d bytes)\n", size);

	/* Encrypt. */
	if (ordoEncrypt((unsigned char*)in, size, (unsigned char*)out, &size, primitive, mode, key, keySize, 0, iv))
	{
		/* Print data AFTER encryption. */
		printf("Ciphertext : ");
		hex(out, size);
		printf(" (%d bytes)\n", size);
	}
	else printf("Ciphertext : ENCRYPTION FAILED!\n");

	/* Decrypt. */
	if (ordoDecrypt((unsigned char*)out, size, (unsigned char*)in, &size, primitive, mode, key, keySize, 0, iv))
	{
		/* Print data AFTER decryption. */
		printf("Plaintext  : ");
		hex(in, size);
		printf(" (%d bytes)\n", size);
	}
	else printf("Plaintext  : DECRYPTION FAILED!\n");

	printf("\n---\n\n");

	free(key);
	free(iv);
	free(in);
	free(out);
}

size_t main(size_t argc, char* argv[])
{
	printf("Loading Ordo... ");
	loadOrdo();
	printf("Loaded!\n");

	printf("\n---\n\n");

	testPrimitiveMode(IDENTITY, ECB, 11, 19);
	testPrimitiveMode(IDENTITY, CTR, 19, 44);
	testPrimitiveMode(IDENTITY, OFB, 19, 23);
	testPrimitiveMode(XORTOY, ECB, 19, 7);
	testPrimitiveMode(XORTOY, CTR, 33, 21);
	testPrimitiveMode(XORTOY, OFB, 33, 49);
	testPrimitiveMode(THREEFISH256, ECB, 64, 32);
	testPrimitiveMode(THREEFISH256, CTR, 112, 32);
	testPrimitiveMode(THREEFISH256, OFB, 112, 32);

	printf("Unloading Ordo... ");
	unloadOrdo();
	printf("Unloaded!\n\n");

	system("pause");
	return 0;
}