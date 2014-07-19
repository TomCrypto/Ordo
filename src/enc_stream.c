/*===-- enc_stream.c ----------------------------------*- generic -*- C -*-===*/

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

#include "ordo/enc/enc_stream.h"

/*===----------------------------------------------------------------------===*/

size_t enc_stream_key_len(prim_t cipher,
                          size_t key_len)
{
    return stream_query(cipher, KEY_LEN_Q, key_len);
}
