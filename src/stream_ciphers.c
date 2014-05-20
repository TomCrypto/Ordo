/*===-- stream_ciphers.c ------------------------------*- generic -*- C -*-===*/

#include "ordo/primitives/stream_ciphers.h"

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

/*===----------------------------------------------------------------------===*/

const char *stream_cipher_name(enum STREAM_CIPHER cipher)
{
    switch (cipher)
    {
#ifdef USING_RC4
        case STREAM_RC4:
            return "RC4";
#endif
        default:
            return 0;
    }
}

/*===----------------------------------------------------------------------===*/

enum STREAM_CIPHER stream_cipher_by_name(const char *name)
{
#ifdef USING_RC4
    if (!strcmp(name, "RC4"))
        return STREAM_RC4;
#endif
    return 0;
}

enum STREAM_CIPHER stream_cipher_by_index(size_t index)
{
    switch (index)
    {
#ifdef USING_RC4
        case __COUNTER__: return STREAM_RC4;
#endif
        default:          return 0;
    }
}

size_t stream_cipher_count(void)
{
    return __COUNTER__;
}

/*===----------------------------------------------------------------------===*/

#include "ordo/primitives/stream_ciphers/rc4.h"

int stream_cipher_init(struct STREAM_STATE *state,
                       const void *key,
                       size_t key_len,
                       enum STREAM_CIPHER primitive,
                       const void *params)
{
    switch (state->primitive = primitive)
    {
#ifdef USING_RC4
        case STREAM_RC4:
            return rc4_init(&state->jmp.rc4, key, key_len, params);
#endif
    }
    
    return ORDO_FAIL;
}

void stream_cipher_update(struct STREAM_STATE *state,
                          void *buffer,
                          size_t len)
{
    switch (state->primitive)
    {
#ifdef USING_RC4
        case STREAM_RC4:
            rc4_update(&state->jmp.rc4, buffer, len);
#endif
    }
}

void stream_cipher_final(struct STREAM_STATE *state)
{
    switch (state->primitive)
    {
#ifdef USING_RC4
        case STREAM_RC4:
            rc4_final(&state->jmp.rc4);
#endif
    }
}

void stream_cipher_copy(struct STREAM_STATE *dst,
                        const struct STREAM_STATE *src)
{
    *dst = *src;
}

size_t stream_cipher_query(enum STREAM_CIPHER primitive,
                           int query, size_t value)
{
    switch (primitive)
    {
#ifdef USING_RC4
        case STREAM_RC4:
            return rc4_query(query, value);
#endif
    }
    
    return (size_t)-1;
}
