/*===-- stream_ciphers.c ------------------------------*- generic -*- C -*-===*/

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

#include "ordo/primitives/stream_ciphers.h"

/*===----------------------------------------------------------------------===*/

#if WITH_RC4
#include "ordo/primitives/stream_ciphers/rc4.h"
#endif

int stream_init(struct STREAM_STATE *state,
                const void *key, size_t key_len,
                prim_t primitive, const void *params)
{
    switch (state->primitive = primitive)
    {
        #if WITH_RC4
        case STREAM_RC4:
            return rc4_init(&state->jmp.rc4, key, key_len, params);
        #endif
    }
    
    return ORDO_ARG;
}

void stream_update(struct STREAM_STATE *state,
                   void *buffer, size_t len)
{
    switch (state->primitive)
    {
        #if WITH_RC4
        case STREAM_RC4:
            rc4_update(&state->jmp.rc4, buffer, len);
            break;
        #endif
    }
}

void stream_final(struct STREAM_STATE *state)
{
    switch (state->primitive)
    {
        #if WITH_RC4
        case STREAM_RC4:
            rc4_final(&state->jmp.rc4);
            break;
        #endif
    }
}

size_t stream_query(prim_t primitive,
                    int query, size_t value)
{
    switch (primitive)
    {
        #if WITH_RC4
        case STREAM_RC4:
            return rc4_query(query, value);
        #endif
    }
    
    return (size_t)-1;
}

size_t stream_bsize(void)
{
    return sizeof(struct STREAM_STATE);
}
