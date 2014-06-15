/*===-- digest.c --------------------------------------*- generic -*- C -*-===*/

#include "ordo/digest/digest.h"

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

/*===----------------------------------------------------------------------===*/

size_t digest_length(prim_t hash)
{
    return hash_function_query(hash, DIGEST_LEN_Q, 0);
}
