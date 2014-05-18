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
        case STREAM_RC4:
            return "RC4";
        case STREAM_UNKNOWN: default:
            return 0;
    }
}

/*===----------------------------------------------------------------------===*/

enum STREAM_CIPHER stream_cipher_by_name(const char *name)
{
    if (!strcmp(name, "RC4"))
        return STREAM_RC4;
    else
        return STREAM_UNKNOWN;
}

enum STREAM_CIPHER stream_cipher_by_index(size_t index)
{
    return index;
}

size_t stream_cipher_count(void)
{
    return STREAM_COUNT;
}

/*===----------------------------------------------------------------------===*/

#include "ordo/primitives/stream_ciphers/rc4.h"

int stream_cipher_init(struct STREAM_STATE *state,
                       const void *key,
                       size_t key_len,
                       enum STREAM_CIPHER cipher,
                       const void *params)
{
    switch (state->cipher = cipher)
    {
        case STREAM_RC4:
            return rc4_init(&state->jmp.rc4, key, key_len, params);
        
        case STREAM_UNKNOWN: default:
            return ORDO_FAIL;
    }
}

void stream_cipher_update(struct STREAM_STATE *state,
                          void *buffer,
                          size_t len)
{
    switch (state->cipher)
    {
        case STREAM_RC4:
            rc4_update(&state->jmp.rc4, buffer, len);

        case STREAM_UNKNOWN: default:
            return;
    }
}

void stream_cipher_final(struct STREAM_STATE *state)
{
    switch (state->cipher)
    {
        case STREAM_RC4:
            rc4_final(&state->jmp.rc4);

        case STREAM_UNKNOWN: default:
            return;
    }
}

void stream_cipher_copy(struct STREAM_STATE *dst,
                        const struct STREAM_STATE *src)
{
    *dst = *src;
}

size_t stream_cipher_query(enum STREAM_CIPHER cipher,
                           int query, size_t value)
{
    switch (cipher)
    {
        case STREAM_RC4:
            return rc4_query(query, value);
        
        case STREAM_UNKNOWN: default:
            return (size_t)-1;
    }
}
