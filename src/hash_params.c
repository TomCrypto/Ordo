/*===-- hash_params.c ---------------------------------*- generic -*- C -*-===*/

#include "ordo/primitives/hash_functions/hash_params.h"

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

/*===----------------------------------------------------------------------===*/

struct SKEIN256_PARAMS skein256_default(void)
{
    struct SKEIN256_PARAMS params = {0};

    params.schema[0] = 0x53; /* S */
    params.schema[1] = 0x48; /* H */
    params.schema[2] = 0x41; /* A */
    params.schema[3] = 0x33; /* 3 */

    params.version[0] = 1; /* "version 1" */
    params.version[1] = 0;

    params.out_len = 256; /* Default length. */

    return params;
}
