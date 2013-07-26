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
 * system library e.g. endian.h under most Unix distributions, however Ordo
 * will try to set up the necessary conversion functions on its own. */

#if defined(PLATFORM_WINDOWS)
    /* For Windows, assume little-endian. Also don't expect Windows to
     * provide endianness functions, you gotta do it all yourself. */
    #define __LITTLE_ENDIAN 1234
    #define __BYTE_ORDER __LITTLE_ENDIAN
#elif defined(PLATFORM_LINUX)
    /* For Linux, endian.h *must* provide the correct definitions. */
    #include <sys/types.h>
    #include <endian.h>
#elif defined(PLATFORM_BSD)
    /* BSD variants use a different system header. */
    #include <sys/types.h>
    #include <sys/endian.h>
#endif

/* Define generic byte swapping macros if they are not already provided. */

#ifndef __bswap_16
    #define __bswap_16(x) (((x) << 8) & 0xff00) | (((x) >> 8 ) & 0xff)
#endif

#ifndef __bswap_32
    #define __bswap_32(x) (((x) << 24) & 0xff000000)  \
                        | (((x) << 8) & 0xff0000)   \
                        | (((x) >> 8) & 0xff00)     \
                        | (((x) >> 24) & 0xff )
#endif

#ifndef __bswap_64
    #define __bswap_64(x) ((((x) & (uint64_t)0xff00000000000000ull) >> 56) \
                        | (((x) & (uint64_t)0x00ff000000000000ull) >> 40) \
                        | (((x) & (uint64_t)0x0000ff0000000000ull) >> 24) \
                        | (((x) & (uint64_t)0x000000ff00000000ull) >> 8) \
                        | (((x) & (uint64_t)0x00000000ff000000ull) << 8) \
                        | (((x) & (uint64_t)0x0000000000ff0000ull) << 24) \
                        | (((x) & (uint64_t)0x000000000000ff00ull) << 40) \
                        | (((x) & (uint64_t)0x00000000000000ffull) << 56))
#endif

/* Endianness helpers: HOST -> BIG-ENDIAN. */

#ifndef htobe16
    #if (__BYTE_ORDER == __LITTLE_ENDIAN)
        #define htobe16(x) (__bswap_16(x))
    #else
        #define htobe16(x) (x)
    #endif
#endif

#ifndef htobe32
    #if (__BYTE_ORDER == __LITTLE_ENDIAN)
        #define htobe32(x) (__bswap_32(x))
    #else
        #define htobe32(x) (x)
    #endif
#endif

#ifndef htobe64
    #if (__BYTE_ORDER == __LITTLE_ENDIAN)
        #define htobe64(x) (__bswap_64(x))
    #else
        #define htobe64(x) (x)
    #endif
#endif

/* Endianness helpers: HOST -> LITTLE-ENDIAN. */

#ifndef htole16
    #if (__BYTE_ORDER == __LITTLE_ENDIAN)
        #define htole16(x) (x)
    #else
        #define htole16(x) (__bswap_16(x))
    #endif
#endif

#ifndef htole32
    #if (__BYTE_ORDER == __LITTLE_ENDIAN)
        #define htole32(x) (x)
    #else
        #define htole32(x) (__bswap_32(x))
    #endif
#endif

#ifndef htole64
    #if (__BYTE_ORDER == __LITTLE_ENDIAN)
        #define htole64(x) (x)
    #else
        #define htole64(x) (__bswap_64(x))
    #endif
#endif

/* Little/big endian to host helpers. */

#ifndef be16toh
    #define be16toh htobe16
#endif

#ifndef be32toh
    #define be32toh htobe32
#endif

#ifndef be64toh
    #define be64toh htobe64
#endif

#ifndef le16toh
    #define le16toh htole16
#endif

#ifndef le32toh
    #define le32toh htole32
#endif

#ifndef le64toh
    #define le64toh htole64
#endif

#ifdef __cplusplus
}
#endif

#endif
