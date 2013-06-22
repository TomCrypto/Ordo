#ifndef ORDO_ENVIRONMENT_H
#define ORDO_ENVIRONMENT_H

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file environment.h
 * \brief Compile-time environment detection.
 *
 * This header will provide definitions for the environment details under
 * which Ordo is being built, trying to unify various compiler-specific
 * details under a single interface.
 *
 * This file may only contain preprocessor macros as it is included in
 * assembly files - it cannot contain declarations.
 *
 * \internal
*/

/* 1. Detect the platform we are going to be building on. If the platform is
 *    invalid, or cannot be detected, or some other reason, fail. */

#if _WIN32 || _WIN64
	#define PLATFORM_WINDOWS 1
#elif __linux__
	#define PLATFORM_LINUX 1
#else
	#error "Platform not supported."
#endif

/* 2. Detect the endianness of the system - normally this is defined by the
 * system library e.g. endian.h under most Unix distributions, however Ordo
 * will try to set up the necessary conversion functions on its own. */

#if PLATFORM_WINDOWS
	/* For Windows, assume little-endian. */
	#define ENDIANNESS 0
#elif PLATFORM_LINUX
	/* For Linux, endian.h *must* provide the correct definitions. */
	#include <endian.h>

	#if __BYTE_ORDER == __LITTLE_ENDIAN
		#define ENDIANNESS 0
	#elif __BYTE_ORDER == __BIG_ENDIAN
		#define ENDIANNESS 1
	#else
		#error "Unknown endianness."
	#endif
#endif

/* 3. Detect if the system is 32-bit or 64-bit. */

#if __LP64__
	#define ENVIRONMENT_64 1
#else
	#define ENVIRONMENT_32 1
#endif

/* These are feature flags used to enable various optimizations. Note these
 * can be overriden via your compiler's options, since they are set from
 * whatever features the compiler reports are available for use. */

/* AES-NI instructions (hardware-accelerated AES) */
#ifdef __AES__
	#define FEATURE_AES 1
#else
	#define FEATURE_AES 0
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
	#define __bswap_64(x) ((((x) & 0xff00000000000000ull) >> 56) \
		                | (((x) & 0x00ff000000000000ull) >> 40) \
		                | (((x) & 0x0000ff0000000000ull) >> 24) \
		                | (((x) & 0x000000ff00000000ull) >> 8) \
		                | (((x) & 0x00000000ff000000ull) << 8) \
		                | (((x) & 0x0000000000ff0000ull) << 24) \
		                | (((x) & 0x000000000000ff00ull) << 40) \
		                | (((x) & 0x00000000000000ffull) << 56))
#endif

/* Endianness helpers: HOST -> BIG-ENDIAN. */

#ifndef htobe16
	#if (ENDIANNESS == 0)
		#define htobe16(x) (__bswap_16(x))
	#else
		#define htobe16(x) (x)
	#endif
#endif

#ifndef htobe32
	#if (ENDIANNESS == 0)
		#define htobe32(x) (__bswap_32(x))
	#else
		#define htobe32(x) (x)
	#endif
#endif

#ifndef htobe64
	#if (ENDIANNESS == 0)
		#define htobe64(x) (__bswap_64(x))
	#else
		#define htobe64(x) (x)
	#endif
#endif

/* Endianness helpers: HOST -> LITTLE-ENDIAN. */

#ifndef htole16
	#if (ENDIANNESS == 0)
		#define htole16(x) (x)
	#else
		#define htole16(x) (__bswap_16(x))
	#endif
#endif

#ifndef htole32
	#if (ENDIANNESS == 0)
		#define htole32(x) (x)
	#else
		#define htole32(x) (__bswap_32(x))
	#endif
#endif

#ifndef htole64
	#if (ENDIANNESS == 0)
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
