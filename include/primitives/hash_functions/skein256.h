#ifndef ORDO_SKEIN256_H
#define ORDO_SKEIN256_H

#include <primitives/primitives.h>

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file skein256.h
 *
 * \brief Skein-256 hash function.
 *
 * This is the Skein-256 hash function, which produces a 256-bit digest by default (but has parameters to output a
 * longer digest) and has a 256-bit internal state. This implementation supports messages up to a length of 2^64 - 1
 * bytes instead of the 2^96 - 1 available, but we trust this will not be an issue. This is a rather flexible hash
 * with lots of options. The following features are marked [x] if available, [ ] otherwise:
 *
 * [x] Simple hashing (256-bit digest, any-length message) \n
 * [x] Variable-length output (any-length digest, any-length message, uses parameters) \n
 * [x] Semi-personalizable configuration block (everything is changeable, but generally you should only change the
 * output length field if you want to remain compliant) \n
 * [ ] Personalization block \n
 * [ ] HMAC block \n
 * [ ] Other blocks \n
 *
 * \todo Expand Skein-256 parameters (add possible extra blocks, such as personalization, hmac, nonce, etc...). This
 * will probably require a rewrite of the UBI subsystem which is rather hardcoded and rigid at the moment.
 *
 * \todo Rewrite the UBI code properly.
 *
 * @see skein256.c
 */

struct SKEIN256_STATE;

/*! Allocates and returns an uninitialized Skein-256 hash function context.
 @returns The allocated context, or nil on allocation failure.
*/
struct SKEIN256_STATE* skein256_alloc();

int skein256_init(struct SKEIN256_STATE *state, const struct SKEIN256_PARAMS* params);

void skein256_update(struct SKEIN256_STATE *state, const void* buffer, size_t size);

void skein256_final(struct SKEIN256_STATE *state, void* digest);

void skein256_free(struct SKEIN256_STATE *state);

void skein256_copy(struct SKEIN256_STATE *dst, const struct SKEIN256_STATE *src);

void skein256_set_primitive(struct HASH_FUNCTION* hash);

#ifdef __cplusplus
}
#endif

#endif
