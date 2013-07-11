#include <misc/os_random.h>

#include <internal/environment.h>
#include <common/errors.h>

/******************************************************************************/

/* Note: if for some reason your platform doesn't have an OS-provided CSPRNG,
 *       please implement this as a function which always returns ORDO_FAIL. */

#if defined(PLATFORM_POSIX)

#include <stdio.h>

int os_random(void *buffer, size_t size)
{
    FILE* f = fopen("/dev/urandom", "r");
    if (!f) return ORDO_FAIL;

    while (size != 0)
    {
        size_t len = fread(buffer, 1, size, f);
        if (len == 0) return ORDO_FAIL;

        buffer = (unsigned char*)buffer + len;
        size -= len;
    }

    fclose(f);

    return ORDO_SUCCESS;
}

#elif defined(PLATFORM_WINDOWS)

#include <windows.h>
#include <Wincrypt.h>

int os_random(void *buffer, size_t size)
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

#else

#error No OS-provided CSPRNG interface implemented for this platform!

#endif
