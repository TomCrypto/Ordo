/*===-- internal/alg.h -------------------------------*- INTERNAL -*- H -*-===*/
/**
*** @file
*** @internal
*** @brief \b Internal, Utility
***
*** This  header provides  various utility  functions which  are used  by some
*** library modules and a few convenience macros. It is not to be used outside
*** the  library, and this is enforced by an include guard. If you really must
*** access it, define the `ORDO_INTERNAL_ACCESS` token before including it.
**/
/*===----------------------------------------------------------------------===*/

#ifndef ORDO_ALG_H
#define ORDO_ALG_H

/** @cond **/
#include "ordo/common/interface.h"
/** @endcond **/

#ifdef __cplusplus
extern "C" {
#endif

/*===----------------------------------------------------------------------===*/

#if !(defined(ORDO_INTERNAL_ACCESS) && defined(ORDO_STATIC_LIB))
    #if !(defined(BUILDING_ORDO) || defined(BUILDING_ordo))
        #error "This header is internal to the Ordo library."
    #endif
#endif

ORDO_HIDDEN void pswap8 (uint8_t  * RESTRICT a, uint8_t  * RESTRICT b);
ORDO_HIDDEN void pswap16(uint16_t * RESTRICT a, uint16_t * RESTRICT b);
ORDO_HIDDEN void pswap32(uint32_t * RESTRICT a, uint32_t * RESTRICT b);
ORDO_HIDDEN void pswap64(uint64_t * RESTRICT a, uint64_t * RESTRICT b);

ORDO_HIDDEN size_t smin(size_t a, size_t b);
ORDO_HIDDEN size_t smax(size_t a, size_t b);

ORDO_HIDDEN uint16_t rol16(uint16_t x, int n);
ORDO_HIDDEN uint16_t ror16(uint16_t x, int n);

ORDO_HIDDEN uint32_t rol32(uint32_t x, int n);
ORDO_HIDDEN uint32_t ror32(uint32_t x, int n);

ORDO_HIDDEN uint64_t rol64(uint64_t x, int n);
ORDO_HIDDEN uint64_t ror64(uint64_t x, int n);

/** Converts bits into bytes (rounded down to the nearest byte boundary).
***
*** @remarks As an example, \c bits(256) returns 32 (bytes).
**/
#define bits(n) (n / 8)

/** Converts bytes into bits (as a multiple of 8 bits).
***
*** @remarks As an example, \c bytes(32) returns 256 (bits).
**/
#define bytes(n) (n * 8)

/** Computes a byte-based offset.
***
*** @param [in]     ptr            Base pointer.
*** @param [in]     len            Offset (in bytes).
***
*** @returns The pointer exactly \c len bytes after \c ptr.
***
*** @remarks This is a dangerous macro, in the  sense it can lead to accessing
***          data at unaligned addresses, and so should be used carefully.
**/
#define offset(ptr, len) ((unsigned char *)ptr + len)

/** Checks whether a buffer conforms to PKCS #7 padding.
***
*** @param [in]     buffer         The buffer to verify, starting at the first
***                                data byte (not at the first padding byte).
*** @param [in]     len            The length in bytes of the buffer.
***
*** @returns The message length if the buffer is valid, or \c 0 otherwise. The
***          message can therefore be recovered as the first N bytes.
***
*** @remarks PKCS padding  is defined as  appending \c N bytes of  padding data
***          at the end of the message, each with  binary value \c N, with \c N
***          between \c 1 and the block size of the block cipher used such that
***          the  length of the message  plus \c N is a  multiple of the  block
***          cipher's block size.
***
*** @warning This implies the buffer must be at least \c padding bytes long.
**/
ORDO_HIDDEN
size_t pad_check(const void *buffer, size_t len);

/** Performs a bitwise exclusive-or of one buffer onto another.
***
*** @param [in,out] dst            The destination buffer.
*** @param [in]     src            The source buffer.
*** @param [in]     len            The number of bytes to process.
***
*** @remarks This is conceptually equivalent to \c dst \c ^= \c src.
***
*** @warning The source and destination buffers may not overlap.
**/
ORDO_HIDDEN
void xor_buffer(void * RESTRICT dst, const void * RESTRICT src, size_t len);

/** Increments a  buffer of arbitrary  length, as though it were a \c len byte
*** integer stored as a byte array.
***
*** @param [in,out] buffer         The buffer to increment in-place.
*** @param [in]     len            The size, in bytes, of the buffer.
***
*** @remarks Carry propagation is done left-to-right.
**/
ORDO_HIDDEN
void inc_buffer(unsigned char *buffer, size_t len);

/*===----------------------------------------------------------------------===*/

#ifdef __cplusplus
}
#endif

#endif
