#ifndef ORDO_ENDIANNESS_H
#define ORDO_ENDIANNESS_H

#include "ordo/internal/environment.h"

/******************************************************************************/

/*!
 * @internal
 * @file endianness.h
 * @brief Compile-time endianness detection.
 *
 * This header will provide definitions relating to endianness. It cannot be
 * included in assembly files as it may or may not contain declarations.
 *
 * This module is not to be used from outside the library, and is only
 * meaningful at compile-time.
*/

#ifdef __cplusplus
extern "C" {
#endif

/* Detect the endianness of the system - normally this is defined by the
 * system library e.g. endian.h under most Unix distributions at least. */

#if defined(PLATFORM_WINDOWS)
    /* For Windows, assume little-endian. Also don't expect Windows to
     * provide endianness functions, you gotta do it all yourself. */
    #define __LITTLE_ENDIAN 1234
    #define __BYTE_ORDER __LITTLE_ENDIAN
    #define ORDO_BUILTIN_SWAP
#elif defined(PLATFORM_LINUX)
    /* For Linux, endian.h *must* provide the correct definitions. */
    #include <sys/types.h>
    #include <endian.h>
#elif defined(PLATFORM_BSD)
    /* BSD variants use a different system header. */
    #include <sys/types.h>
    #include <sys/endian.h>
#endif

#if defined(ORDO_BUILTIN_SWAP)

    #define __bswap_16(x) ((((x) << 8) & 0xff00) \
                         | (((x) >> 8 ) & 0xff))

    #define __bswap_32(x) ((((x) << 24) & 0xff000000) \
                         | (((x) << 8) & 0xff0000)    \
                         | (((x) >> 8) & 0xff00)      \
                         | (((x) >> 24) & 0xff))

    #define __bswap_64(x) ((((x) & (uint64_t)0xff00000000000000ULL) >> 56) \
                         | (((x) & (uint64_t)0x00ff000000000000ULL) >> 40) \
                         | (((x) & (uint64_t)0x0000ff0000000000ULL) >> 24) \
                         | (((x) & (uint64_t)0x000000ff00000000ULL) >> 8)  \
                         | (((x) & (uint64_t)0x00000000ff000000ULL) << 8)  \
                         | (((x) & (uint64_t)0x0000000000ff0000ULL) << 24) \
                         | (((x) & (uint64_t)0x000000000000ff00ULL) << 40) \
                         | (((x) & (uint64_t)0x00000000000000ffULL) << 56))

    #if (__BYTE_ORDER == __LITTLE_ENDIAN)
        #define htobe16(x) (__bswap_16(x))
        #define htobe32(x) (__bswap_32(x))
        #define htobe64(x) (__bswap_64(x))
        #define htole16(x) (x)
        #define htole32(x) (x)
        #define htole64(x) (x)
        
        #define be16toh(x) (__bswap_16(x))
        #define be32toh(x) (__bswap_32(x))
        #define be64toh(x) (__bswap_64(x))
        #define le16toh(x) (x)
        #define le32toh(x) (x)
        #define le64toh(x) (x)
    #else
        #define htole16(x) (__bswap_16(x))
        #define htole32(x) (__bswap_32(x))
        #define htole64(x) (__bswap_64(x))
        #define htobe16(x) (x)
        #define htobe32(x) (x)
        #define htobe64(x) (x)
        
        #define le16toh(x) (__bswap_16(x))
        #define le32toh(x) (__bswap_32(x))
        #define le64toh(x) (__bswap_64(x))
        #define be16toh(x) (x)
        #define be32toh(x) (x)
        #define be64toh(x) (x)
    #endif
#endif

#ifdef __cplusplus
}
#endif

#endif
