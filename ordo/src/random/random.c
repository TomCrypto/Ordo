#include <random/random.h>

#if PLATFORM_LINUX

#include <stdio.h>

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

        /* Move the buffer forward to prepare to read the rest. */
        buffer += len;
        size -= len;
    }

    /* Close and return. */
    fclose(f);
    return ORDO_ESUCCESS;
}

#elif PLATFORM_WINDOWS

#include <windows.h>
#include <Wincrypt.h>

int ordoRandom(unsigned char* buffer, size_t size)
{
    /* Acquire a CSP token. */
    HCRYPTPROV hProv;
    CryptAcquireContext(&hProv, 0, 0, PROV_RSA_FULL, 0); // ?
    if (hProv == 0) return ORDO_EFAIL;

    /* Generate pseudorandom bytes. */
    CryptGenRandom(hProv, size, (BYTE*)buffer);
    CryptReleaseContext(hProv, 0);
    return ORDO_ESUCCESS;
}

#else
#error "Unknown platform."
#endif
