/*===-- digest.c --------------------------------------*- generic -*- C -*-===*/

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

#include "ordo/digest/digest.h"

/*===----------------------------------------------------------------------===*/

size_t digest_length(prim_t hash)
{
    return hash_query(hash, DIGEST_LEN_Q, 0);
}
