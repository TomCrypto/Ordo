/*===-- enc_stream.c ----------------------------------*- generic -*- C -*-===*/

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

#include "ordo/enc/enc_stream.h"

/*===----------------------------------------------------------------------===*/

size_t enc_stream_key_len(prim_t cipher,
                          size_t key_len)
{
    struct STREAM_LIMITS limits;

    if (stream_limits(cipher, &limits))
        return 0;

    return limit_constrain(key_len,
                           limits.key_min,
                           limits.key_max,
                           limits.key_mul);
}
