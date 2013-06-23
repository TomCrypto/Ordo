#include <primitives/block_ciphers/nullcipher.h>

#include <common/ordo_errors.h>
#include <common/secure_mem.h>

/******************************************************************************/

#define NULLCIPHER_BLOCK (16)

struct NULLCIPHER_STATE
{
    size_t dummy;
};

struct NULLCIPHER_STATE* nullcipher_alloc()
{
    /* A block cipher always needs to allocate some state (returning nil means
       an allocation failed, so we can't use that even for this cipher). */
    return secure_alloc(sizeof(struct NULLCIPHER_STATE));
}

int nullcipher_init(struct NULLCIPHER_STATE *state,
                    const void* key, size_t keySize,
                    const void* params)
{
    return ORDO_SUCCESS;
}

void nullcipher_forward(struct NULLCIPHER_STATE *state, void* block)
{
    return;
}

void nullcipher_inverse(struct NULLCIPHER_STATE *state, void* block)
{
    return;
}

void nullcipher_free(struct NULLCIPHER_STATE *state)
{
    secure_free(state, sizeof(struct NULLCIPHER_STATE));
}

void nullcipher_copy(struct NULLCIPHER_STATE *dst,
                     const struct NULLCIPHER_STATE *src)
{
    dst->dummy = src->dummy; /* Example. */
}

void nullcipher_set_primitive(struct BLOCK_CIPHER* cipher)
{
    make_block_cipher(cipher,
                      NULLCIPHER_BLOCK,
                      (BLOCK_ALLOC)nullcipher_alloc,
                      (BLOCK_INIT)nullcipher_init,
                      (BLOCK_UPDATE)nullcipher_forward,
                      (BLOCK_UPDATE)nullcipher_inverse,
                      (BLOCK_FREE)nullcipher_free,
                      (BLOCK_COPY)nullcipher_copy,
                      "NullCipher");
}
