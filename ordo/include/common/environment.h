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
 * This header will provide definitions for the environment details under which Ordo is being built. This is useful if
 * you need to use code for a specific platform (say an optimized assembly implementation for x86 processors, and a
 * standard C implementation for everything else) - in this case, you would include this header in your code and use
 * the preprocessor to include and exclude code depending on the platform, word size, CPU features, etc...
 *
 * Make sure to keep this updated and consistent whenever a new platform is added, otherwise it will refuse to compile.
 * Note the users should never need to interact with this header when using Ordo - this is meant for internal use only.
 *
 * This file may only contain preprocessor macros as it is included in assembly files - it cannot contain declarations.
 *
 * \todo Add environmental symbols for more platforms (e.g. Mac) and possibly compilers.
 *
 */

/* These are environment flags, which must be set to sensible values. */

/* Decides what platform Ordo is being compiled under. */
#if _WIN32 || _WIN64
	#define PLATFORM_WINDOWS 1
#elif __linux__
	#define PLATFORM_LINUX 1
#endif

/* Decides whether the build target is a 32-bit or 64-bit platform. */
#if _WIN64 || __amd64__ || __x86_64__ || __ppc64__
	#define ENVIRONMENT_64 1
#else
	#define ENVIRONMENT_32 1
#endif

/* Represents which ABI (for pure assembler functions) is in use. Possible values are:
 * ABI_WINDOWS_64: 64-bit Windows calling convention.
 * ABI_LINUX_64  : 64-bit Linux calling convention.
 * ABI_CDECL     : Standard cdecl calling convention. */
#if ENVIRONMENT_64 && PLATFORM_WINDOWS
	#define ABI_WINDOWS_64 1
#elif ENVIRONMENT_64 && PLATFORM_LINUX
	#define ABI_LINUX_64 1
#elif ENVIRONMENT_32
	#define ABI_CDECL 1
#endif

#if !(PLATFORM_WINDOWS || PLATFORM_LINUX)
	#error "Cannot recognize platform."
#endif

#if !(ENVIRONMENT_64 || ENVIRONMENT_32)
	#error "Cannot recognize environment."
#endif

#if !(ABI_WINDOWS_64 || ABI_LINUX_64 || ABI_CDECL)
	#error "Cannot recognize calling convention."
#endif

/* Work out the endianness of the platform. Normally this is defined by the
 * system library e.g. endian.h under most Unix distributions, however Ordo
 * will try to set up the necessary conversion functions if the system does
 * not provide them. Later it will be possible to specify build options. */

/* For now we assume little-endian if not system-provided. Figure it out
 * later. */

#if PLATORM_WINDOWS
	#ifndef __BYTE_ORDER
		#define __BYTE_ORDER __LITTLE_ENDIAN
	#endif
#elif PLATFORM_LINUX
	#include <endian.h>

	#ifndef __BYTE_ORDER
		#define __BYTE_ORDER __LITTLE_ENDIAN
	#endif
#endif

/* These are feature flags used to enable various optimizations. Note these can be overriden via your compiler's
 * options, since they are set from whatever features the compiler reports are available for use. */

#ifdef __MMX__                  /* MMX instructions (64-bit SIMD) */
	#define FEATURE_MMX 1
#else
	#define FEATURE_MMX 0
#endif

#ifdef __SSE__                  /* SSE instructions (128-bit SIMD, v1) */
	#define FEATURE_SSE 1
#else
	#define FEATURE_SSE 0
#endif

#ifdef __SSE2__                 /* SSE instructions (128-bit SIMD, v2) */
	#define FEATURE_SSE2 1
#else
	#define FEATURE_SSE2 0
#endif

#ifdef __SSE3__                 /* SSE instructions (128-bit SIMD, v3) */
	#define FEATURE_SSE3 1
#else
	#define FEATURE_SSE3 0
#endif

#ifdef __SSE4_1__               /* SSE instructions (128-bit SIMD, v4.1) */
	#define FEATURE_SSE4_1 1
#else
	#define FEATURE_SSE4_1 0
#endif

#ifdef __SSE4_2__               /* SSE instructions (128-bit SIMD, v4.2) */
	#define FEATURE_SSE4_2 1
#else
	#define FEATURE_SSE4_2 0
#endif

#ifdef __AVX__                  /* AVX instructions (256-bit SIMD) */
	#define FEATURE_AVX 1
#else
	#define FEATURE_AVX 0
#endif

#ifdef __AES__                  /* AES-NI instructions (hardware-accelerated AES) */
	#define FEATURE_AES 1
#else
	#define FEATURE_AES 0
#endif

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

/* Endianness reverse helpers (trivial by reflexivity). */

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
