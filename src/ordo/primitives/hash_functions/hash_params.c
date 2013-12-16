#include "ordo/primitives/hash_functions/hash_params.h"

#include <string.h>

struct SKEIN256_PARAMS ORDO_CALLCONV
skein256_default(void)
{
    struct SKEIN256_PARAMS params;
    
    memset(&params, 0x00, sizeof(params));
    
    params.schema[0] = 0x53; /* S */
    params.schema[1] = 0x48; /* H */
    params.schema[2] = 0x41; /* A */
    params.schema[3] = 0x33; /* 3 */
    
    params.version[0] = 1; /* "version 1" */
    params.version[1] = 0;
    
    params.out_len = 256; /* Default length. */
    
    return params;
}
