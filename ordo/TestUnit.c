// Ordo.cpp : Defines the entry posize_t for the console application.
//

#include <stdio.h>
#include <Windows.h>
#include "cipher.h"

/* Binary to hex. */
void hex(char* input, size_t len)
{
	size_t t;
	for (t = 0; t < len; t++) printf("%.2x", (unsigned char)*(input + t));
}

void testPrimitiveMode(CIPHER_PRIMITIVE primitive, CIPHER_MODE mode)
{
	size_t size;
	char buffer[32] = "hello world";
	char iv[16] =     "this is an IV!!";
	char iv2[32] =     "this isa considerably longer IV";
	void* key;

	key = malloc(primitive.szRawKey);
	memset(key, 0xCA, primitive.szRawKey);

	size = 11;
	printf("Cipher: %s | Mode: %s\n", primitive.name, mode.name);
	printf("Plaintext  : ");
	hex(buffer, size);
	printf(" (%d bytes)\n", size);
	
	if (primitive.szTweak != 0)
	{
		cipherEncrypt((char*)buffer, &size, primitive, mode, key, 0, iv2);
	}
	else
	{
		cipherEncrypt((char*)buffer, &size, primitive, mode, key, 0, iv);
	}

	printf("Ciphertext : ");
	hex(buffer, size);
	printf(" (%d bytes)\n", size);

	if (primitive.szTweak != 0)
	{
		cipherDecrypt((char*)buffer, &size, primitive, mode, key, 0, iv2);
	}
	else
	{
		cipherDecrypt((char*)buffer, &size, primitive, mode, key, 0, iv);
	}

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

	testPrimitiveMode(IDENTITY, ECB);
	testPrimitiveMode(IDENTITY, CTR);
	testPrimitiveMode(XORTOY, ECB);
	testPrimitiveMode(XORTOY, CTR);
	testPrimitiveMode(THREEFISH, CTR);

	system("pause");
	return 0;
}

