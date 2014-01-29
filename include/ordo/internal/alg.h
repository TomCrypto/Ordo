//===-- internal/alg.h --------------------------------*- INTERNAL-*- H -*-===//
///
/// @file
/// @internal
/// @brief \b Internal, Utility
///
/// This  header provides  various utility  functions which  are used  by some
/// library modules and a few convenience macros. It is not to be used outside
/// the  library, and this is enforced by an include guard. If you really must
/// access it, define the `ORDO_INTERNAL_ACCESS` token before including it.
///
/// Functions in internal headers are not prefixed, be wary of name clashes.
///
//===----------------------------------------------------------------------===//

#ifndef ORDO_ALG_H
#define ORDO_ALG_H

/// @cond
#include "ordo/common/interface.h"
/// @endcond

#ifdef __cplusplus
extern "C" {
#endif

//===----------------------------------------------------------------------===//

#if !(defined(ORDO_INTERNAL_ACCESS) && defined(ORDO_STATIC_LIB))
    #if !(defined(BUILDING_ORDO) || defined(BUILDING_ordo))
        #error "This header is internal to the library."
    #endif
#endif

ORDO_HIDDEN void pswap8 (uint8_t  *a, uint8_t  *b);
ORDO_HIDDEN void pswap16(uint16_t *a, uint16_t *b);
ORDO_HIDDEN void pswap32(uint32_t *a, uint32_t *b);
ORDO_HIDDEN void pswap64(uint64_t *a, uint64_t *b);

ORDO_HIDDEN size_t smin(size_t a, size_t b);
ORDO_HIDDEN size_t smax(size_t a, size_t b);

ORDO_HIDDEN uint16_t rol16(uint16_t x, int n);
ORDO_HIDDEN uint16_t ror16(uint16_t x, int n);

ORDO_HIDDEN uint32_t rol32(uint32_t x, int n);
ORDO_HIDDEN uint32_t ror32(uint32_t x, int n);

ORDO_HIDDEN uint64_t rol64(uint64_t x, int n);
ORDO_HIDDEN uint64_t ror64(uint64_t x, int n);

/// Converts bits into bytes (rounded down to the nearest byte boundary).
///
/// @remarks As an example, \c bits(256) returns 32 (bytes).
#define bits(n) (n / 8)

/// Converts bytes into bits (as a multiple of 8 bits).
///
/// @remarks As an example, \c bytes(32) returns 256 (bits).
#define bytes(n) (n * 8)

/// Computes a byte-based offset.
///
/// @param [in]     ptr            Base pointer.
/// @param [in]     len            Offset (in bytes).
///
/// @returns The pointer exactly \c len bytes after \c ptr.
///
/// @remarks This is a dangerous macro, in the  sense it can lead to accessing
///          data at unaligned addresses, and so should be used carefully.
#define offset(ptr, len) ((unsigned char *)ptr + len)

/// Checks whether a buffer conforms to PKCS padding.
///
/// @param [in]     buffer         The buffer to check, starting  at the first
///                                padding byte.
/// @param [in]     padding        The padding byte value to check this buffer
///                                against (between 1 and 255).
///
/// @returns \c 1 if the buffer is valid, \c 0 otherwise.
///
/// @remarks PKCS padding  is defined as  appending \c N bytes of  padding data
///          at the end of the message, each with  binary value \c N, with \c N
///          between \c 1 and the block size of the block cipher used such that
///          the  length of the message  plus \c N is a  multiple of the  block
///          cipher's block size.
///
/// @remarks This implies the buffer must be at least \c padding bytes long.
ORDO_HIDDEN
int pad_check(const unsigned char *buffer, uint8_t padding);

/// Performs a bitwise exclusive-or of one buffer onto another.
///
/// @param [in,out] dst            The destination buffer.
/// @param [in]     src            The source buffer.
/// @param [in]     len            The number of bytes to process.
///
/// @remarks This is conceptually equivalent to \c dst \c ^= \c src.
///
/// @remarks The Source and destination buffers may be the same (in which case
///          the buffer will contain \c len zeroes), but otherwise they cannot
///          overlap.
ORDO_HIDDEN
void xor_buffer(void *dst, const void *src, size_t len);

/// Increments a  buffer of arbitrary  length, as though it were a \c len byte
/// integer stored as a byte array.
///
/// @param [in,out] buffer         The buffer to increment in-place.
/// @param [in]     len            The size, in bytes, of the buffer.
///
/// @remarks Carry propagation is done left-to-right.
ORDO_HIDDEN
void inc_buffer(unsigned char *buffer, size_t len);

//===----------------------------------------------------------------------===//

#ifdef __cplusplus
}
#endif

#endif
