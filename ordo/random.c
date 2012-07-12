/**
 * @file random.c
 * Implements the Ordo CSPRNG, which is basically a cross-platform wrapper to the OS-provided entropy pool.
 *
 * \todo Check Linux /dev/urandom version, and implement it for other platforms.
 *
 * @see random.h
 */

#include "random.h"

#if defined __linux__

#include <stdio.h>

/*! Generates cryptographic-grade pseudorandom numbers. */
void random(void* buffer, size_t size)
{
	/* Not checked. */
	size_t read;
	size_t pos = 0;
	FILE* f = fopen("/dev/urandom", "r");

	while (size != 0)
	{
		read = fread(buffer + pos, 1, size, f);
		pos += read;
		size -= read;
	}

	fclose(f);
}

#elif defined _WIN32 || defined _WIN64

#include <Windows.h>

/*! Generates cryptographic-grade pseudorandom numbers. */
void random(void* buffer, size_t size)
{
	HCRYPTPROV hProv;
	CryptAcquireContext(&hProv, 0, 0, PROV_RSA_FULL, 0);
	CryptGenRandom(hProv, size, (BYTE*)buffer);
	CryptReleaseContext(hProv, 0);
}

#else
#error "Unknown platform."
#endif
