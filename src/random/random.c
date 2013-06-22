#include <random/random.h>

#include <internal/environment.h>
#include <common/ordo_errors.h>

/******************************************************************************/

#if PLATFORM_LINUX

#include <stdio.h>

int ordo_random(unsigned char* buffer, size_t size)
{
    FILE* f = fopen("/dev/urandom", "r");
    if (!f) return ORDO_FAIL;

    while (size != 0)
    {
        size_t len = fread(buffer, 1, size, f);
        if (len == 0) return ORDO_FAIL;

        buffer += len;
        size -= len;
    }

    fclose(f);

    return ORDO_SUCCESS;
}

#elif PLATFORM_WINDOWS

#include <windows.h>
#include <Wincrypt.h>

int ordo_random(unsigned char* buffer, size_t size)
{
    /* Acquire a CSP token. */
    HCRYPTPROV hProv;
    CryptAcquireContext(&hProv, 0, 0, PROV_RSA_FULL, 0); /* ? */
    if (hProv == 0) return ORDO_FAIL;

    /* Generate pseudorandom bytes. */
    CryptGenRandom(hProv, size, (BYTE*)buffer);
    CryptReleaseContext(hProv, 0);
    return ORDO_SUCCESS;
}

#endif
