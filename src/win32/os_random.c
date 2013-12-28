//===-- os_random.c -------------------------------------*- win32 -*- C -*-===//

#include "ordo/misc/os_random.h"

/// @cond
#include "ordo/internal/implementation.h"
/// @endcond

#include <windows.h>
#include <wincrypt.h>

//===----------------------------------------------------------------------===//

int os_random(void *buffer, size_t size)
{
    HCRYPTPROV hProv;
    if (CryptAcquireContext(&hProv, 0, 0, PROV_RSA_FULL,
                            CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
    {
        int err = CryptGenRandom(hProv, (DWORD)size, (BYTE*)buffer)
                ? ORDO_SUCCESS : ORDO_FAIL;

        CryptReleaseContext(hProv, 0);
        return err;
    }

    return ORDO_FAIL;
}
