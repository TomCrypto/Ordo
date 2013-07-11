#include <primitives/block_ciphers/nullcipher.h>

#include <common/errors.h>
#include <common/utils.h>
#include <internal/mem.h>

/******************************************************************************/

#define NULLCIPHER_BLOCK (bits(128)) /* This is arbitrary. */

struct NULLCIPHER_STATE
{
    size_t dummy;
};

struct NULLCIPHER_STATE* nullcipher_alloc(void)
{
    /* A block cipher always needs to allocate a state (returning nil means
       an allocation failed, so we can't use that even for this cipher). */
    return mem_alloc(sizeof(struct NULLCIPHER_STATE));
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
    mem_free(state);
}

void nullcipher_copy(struct NULLCIPHER_STATE *dst,
                     const struct NULLCIPHER_STATE *src)
{
    dst->dummy = src->dummy; /* Example. */
}

size_t nullcipher_key_len(size_t key_len)
{
    return 0;
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
                      (BLOCK_KEYLEN)nullcipher_key_len,
                      "NullCipher");
}
