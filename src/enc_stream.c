/*===-- enc_stream.c ----------------------------------*- generic -*- C -*-===*/

#include "ordo/enc/enc_stream.h"

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

/*===----------------------------------------------------------------------===*/

size_t enc_stream_key_len(prim_t cipher,
                          size_t key_len)
{
    return stream_cipher_query(cipher, KEY_LEN_Q, key_len);
}
