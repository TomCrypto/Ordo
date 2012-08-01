#include <stdio.h>
#include <time.h>
#include "ordo.h"

/* Binary to hex. */
void hex(void* input, size_t len)
{
	size_t t;
	for (t = 0; t < len; t++) printf("%.2x", (unsigned char)*((char*)input + t));
}

void testPrimitiveMode(CIPHER_PRIMITIVE* primitive, ENCRYPT_MODE* mode, size_t size, size_t keySize, int padding)
{
	/* Declare variables. */
	void* in;
	void* out;
	void* iv;
	void* key;
	size_t pad;

	/* Store the size and pad it up to the block size (this is only needed for ECB/CBC/etc... but it will be ignored for streaming modes, the extra space will simply be disregarded by the API) */
	if (size % primitiveBlockSize(primitive) == 0) pad = size + primitiveBlockSize(primitive);
	else pad = size + primitiveBlockSize(primitive) - size % primitiveBlockSize(primitive);

	/* Allocate a plaintext buffer and fill it with 0x77 bytes.*/
	in = malloc(size);
	memset(in, 0x77, size);

	/* Allocate a ciphertext buffer.*/
	out = malloc(pad);

	/* Allocate a buffer of the right size (= cipher block size) and fill it with 0xAA. */
	iv = malloc(primitiveBlockSize(primitive));
	memset(iv, 0xAA, primitiveBlockSize(primitive));

	/* Allocate a key of the right sie, and fill it with 0xEE. */
	key = malloc(keySize);
	memset(key, 0xEE, keySize);

	/* Print data BEFORE encryption. */
	printf("Cipher: %s | Mode: %s (key length = %zu bits)\n", primitiveName(primitive), modeName(mode), keySize * 8);
	printf("Plaintext  : ");
	hex(in, size);
	printf(" (%zu bytes)\n", size);

	/* Encrypt. */
	if (ordoEncrypt((unsigned char*)in, size, (unsigned char*)out, &size, primitive, mode, key, keySize, 0, iv, padding) == 0)
	{
		/* Print data AFTER encryption. */
		printf("Ciphertext : ");
		hex(out, size);
		printf(" (%zu bytes)\n", size);
	}
	else printf("Ciphertext : ENCRYPTION FAILED!\n");

	/* Decrypt. */
	if (ordoDecrypt((unsigned char*)out, size, (unsigned char*)in, &size, primitive, mode, key, keySize, 0, iv, padding) == 0)
	{
		/* Print data AFTER decryption. */
		printf("Plaintext  : ");
		hex(in, size);
		printf(" (%zu bytes)\n", size);
	}
	else printf("Plaintext  : DECRYPTION FAILED!\n");

	printf("\n---\n\n");

	free(key);
	free(iv);
	free(in);
	free(out);
}

/* Clears a buffer with a pseudorandom integer pattern. */
void randomize(unsigned char* buffer, size_t len)
{
    /* Get a pseudorandom integer. */
    int r;
    if (ordoRandom((unsigned char*)&r, sizeof(r)) == 1) printf("ordoRandom FAILED!\n");

    /* Fill the buffer with it. */
    memset(buffer, r, len);
}

void ratePrimitiveMode(CIPHER_PRIMITIVE* primitive, ENCRYPT_MODE* mode, size_t keySize)
{
	/* Buffer size. */
	#define BUFSIZE (1024 * 1024 * 128)

	/* Declare variables. */
	void* in;
	void* out;
	void* iv;
	void* key;
	size_t outlen;
	clock_t start;
	float time;

	/* Allocate a large plaintext buffer and fill it with 0x77 bytes.*/
	in = malloc(BUFSIZE);
	randomize(in, BUFSIZE);

	/* Allocate a ciphertext buffer.*/
	out = malloc(BUFSIZE);

	/* Allocate a buffer of the right size (= cipher block size) and fill it with 0xAA. */
	iv = malloc(primitiveBlockSize(primitive));
	randomize(iv, primitiveBlockSize(primitive));

	/* Allocate a key of the right sie, and fill it with 0xEE. */
	key = malloc(keySize);
	randomize(key, keySize);

	/* Print information data. */
	printf("Cipher: %s | Mode: %s (key length = %zu bits)\n", primitiveName(primitive), modeName(mode), keySize * 8);
	printf("Starting performance test...\n");

	/* Save starting time. */
	start = clock();

	/* Encrypt. */
	if (ordoEncrypt((unsigned char*)in, BUFSIZE, (unsigned char*)out, &outlen, primitive, mode, key, keySize, 0, iv, 0) == 0)
	{
		/* Get total time and display speed. */
		start = clock() - start;
		time = (float)start / (float)CLOCKS_PER_SEC;
		printf("It took %.2f seconds to encrypt %dMB - Rated speed at %.1fMB/s.\n", time, BUFSIZE >> 20, (float)(BUFSIZE >> 20) / time);
	}
	else printf("An error occurred during encryption.");

	/* Reset the buffer to prevent caching from tainting the subsequent timings. */
	randomize(in, BUFSIZE);
	randomize(out, BUFSIZE);

	/* Save starting time. */
	start = clock();

	/* Decrypt. */
	if (ordoDecrypt((unsigned char*)in, BUFSIZE, (unsigned char*)out, &outlen, primitive, mode, key, keySize, 0, iv, 0) == 0)
	{
		/* Get total time and display speed. */
		start = clock() - start;
		time = (float)start / (float)CLOCKS_PER_SEC;
		printf("It took %.2f seconds to decrypt %dMB - Rated speed at %.1fMB/s.\n", time, BUFSIZE >> 20, (float)(BUFSIZE >> 20) / time);
	}
	else printf("An error occurred during decryption.");

	printf("\n---\n\n");

	free(key);
	free(iv);
	free(in);
	free(out);
}

void csprngTest()
{
	/* Create a small 100-byte buffer. */
	size_t t;
	void* buffer = malloc(100);

	/* Get random data, a few times. */
	printf("Generating random data...\n");
	for (t = 0; t < 31; t++)
	{
		if (ordoRandom(buffer, 100) == 0)
		{
		    hex(buffer, 100);
            printf("\n");
		}
		else printf("Error!\n");
	}
	printf("Generation complete.\n\n---\n\n");
}

int main(int argc, char* argv[])
{
    printf("################\n");
    #ifdef ENVIRONMENT64
    printf("# 64-bit mode! #\n################\n\n");
    #else
    printf("# 32-bit mode! #\n################\n\n");
    #endif

	printf("Loading Ordo... ");
	loadOrdo();
	printf("Loaded!\n");

	printf("\n---\n\n");
	printf("* STARTING ENCRYPTION TESTS...\n\n---\n\n");

	testPrimitiveMode(NullCipher, ECB, 11, 19, 1);
	testPrimitiveMode(NullCipher, CBC, 44, 19, 1);
	testPrimitiveMode(NullCipher, CTR, 19, 44, 0);
	testPrimitiveMode(NullCipher, OFB, 17, 23, 0);
	testPrimitiveMode(NullCipher, CFB, 41, 23, 0);
	testPrimitiveMode(Threefish256, ECB, 64, 32, 1);
	testPrimitiveMode(Threefish256, CBC, 64, 32, 1);
	testPrimitiveMode(Threefish256, CTR, 112, 32, 0);
	testPrimitiveMode(Threefish256, OFB, 112, 32, 0);
	testPrimitiveMode(Threefish256, CFB, 112, 32, 0);
	testPrimitiveMode(RC4, STREAM, 71, 41, 0);

	printf("* STARTING PERFORMANCE TESTS...\n\n---\n\n");

	ratePrimitiveMode(NullCipher, ECB, 16);
	ratePrimitiveMode(NullCipher, CBC, 16);
	ratePrimitiveMode(NullCipher, CTR, 16);
	ratePrimitiveMode(NullCipher, OFB, 16);
	ratePrimitiveMode(NullCipher, CFB, 16);
	ratePrimitiveMode(Threefish256, ECB, 32);
	ratePrimitiveMode(Threefish256, CBC, 32);
	ratePrimitiveMode(Threefish256, CTR, 32);
	ratePrimitiveMode(Threefish256, OFB, 32);
	ratePrimitiveMode(Threefish256, CFB, 32);
	ratePrimitiveMode(RC4, STREAM, 64);

	printf("* STARTING CSPRNG TEST...\n\n---\n\n");
	csprngTest();

	printf("Unloading Ordo... ");
	unloadOrdo();
	printf("Unloaded!\n\n");

	return 0;
}
