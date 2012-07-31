/**
 * @file random.c
 * Implements the Ordo CSPRNG, which is basically a cross-platform wrapper to the OS-provided entropy pool.
 *
 * Linux: Reads from /dev/urandom.
 *
 * Windows: Acquires a CSP token and calls CryptGenRandom.
 *
 * \todo Implement ordoRandom for other platforms and add error handling for Windows.
 *
 * @see random.h
 */

#include "random.h"

#if defined __linux__

#include <stdio.h>

/*! Generates cryptographic-grade pseudorandom numbers. */
int ordoRandom(unsigned char* buffer, size_t size)
{
	size_t len;

	/* Open /dev/urandom. */
	FILE* f = fopen("/dev/urandom", "r");
	if (f == 0) return ORDO_EFAIL;

	while (size != 0)
	{
	    /* Read pseudorandom bytes. */
	    len = fread(buffer, 1, size, f);

	    /* If no bytes were read, an error occurred. */
        if (len == 0) return ORDO_EFAIL;

	    /* Move the buffer forward. */
	    buffer += len;
	    size -= len;
	}

	/* Close and return. */
	fclose(f);
	return 0;
}

#elif defined _WIN32 || defined _WIN64

#include <windows.h>
#include <Wincrypt.h>

/*! Generates cryptographic-grade pseudorandom numbers. */
int ordoRandom(unsigned char* buffer, size_t size)
{
	HCRYPTPROV hProv;
	CryptAcquireContext(&hProv, 0, 0, PROV_RSA_FULL, 0);
	CryptGenRandom(hProv, size, (BYTE*)buffer);
	CryptReleaseContext(hProv, 0);
	return 0;
}

#else
#error "Unknown platform."
#endif
