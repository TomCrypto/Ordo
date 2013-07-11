#include <enc/block_modes.h>

#include <common/identification.h>

#include <string.h>

#include <enc/block_cipher_modes/ecb.h>
#include <enc/block_cipher_modes/cbc.h>
#include <enc/block_cipher_modes/ctr.h>
#include <enc/block_cipher_modes/cfb.h>
#include <enc/block_cipher_modes/ofb.h>

/******************************************************************************/

struct BLOCK_MODE
{
    BLOCK_MODE_ALLOC alloc;
    BLOCK_MODE_INIT init;
    BLOCK_MODE_UPDATE update;
    BLOCK_MODE_FINAL final;
    BLOCK_MODE_FREE free;
    BLOCK_MODE_COPY copy;
    const char* name;
};

void make_block_mode(struct BLOCK_MODE *mode,
                     BLOCK_MODE_ALLOC alloc,
                     BLOCK_MODE_INIT init,
                     BLOCK_MODE_UPDATE update,
                     BLOCK_MODE_FINAL final,
                     BLOCK_MODE_FREE free,
                     BLOCK_MODE_COPY copy,
                     const char *name)
{
    mode->alloc = alloc;
    mode->init = init;
    mode->update = update;
    mode->final = final;
    mode->free = free;
    mode->copy = copy;
    mode->name = name;
}

/******************************************************************************/

struct BLOCK_MODE encryptModes[BLOCK_MODE_COUNT];

void load_block_modes(void)
{
    ecb_set_mode(&encryptModes[BLOCK_MODE_ECB]);
    cbc_set_mode(&encryptModes[BLOCK_MODE_CBC]);
    ctr_set_mode(&encryptModes[BLOCK_MODE_CTR]);
    cfb_set_mode(&encryptModes[BLOCK_MODE_CFB]);
    ofb_set_mode(&encryptModes[BLOCK_MODE_OFB]);
}

const struct BLOCK_MODE* ECB(void)
{
    return &encryptModes[BLOCK_MODE_ECB];
}

const struct BLOCK_MODE* CBC(void)
{
    return &encryptModes[BLOCK_MODE_CBC];
}

const struct BLOCK_MODE* CTR(void)
{
    return &encryptModes[BLOCK_MODE_CTR];
}

const struct BLOCK_MODE* CFB(void)
{
    return &encryptModes[BLOCK_MODE_CFB];
}

const struct BLOCK_MODE* OFB(void)
{
    return &encryptModes[BLOCK_MODE_OFB];
}

/******************************************************************************/

const char* block_mode_name(const struct BLOCK_MODE *mode)
{
    return mode->name;
}

/******************************************************************************/

const struct BLOCK_MODE* block_mode_by_name(const char* name)
{
    size_t t;
    for (t = 0; t < BLOCK_MODE_COUNT; t++)
    {
        if (strcmp(name, encryptModes[t].name) == 0)
            return &encryptModes[t];
    }

    return 0;
}

const struct BLOCK_MODE* block_mode_by_id(size_t id)
{
    return (id < BLOCK_MODE_COUNT) ? &encryptModes[id] : 0;
}

/******************************************************************************/

void* block_mode_alloc(const struct BLOCK_MODE* mode,
                       const struct BLOCK_CIPHER *cipher,
                       void* cipher_state)
{
    return mode->alloc(cipher, cipher_state);
}

int block_mode_init(const struct BLOCK_MODE *mode,
                    void *state,
                    const struct BLOCK_CIPHER *cipher,
                    void* cipher_state,
                    const void* iv,
                    size_t iv_len,
                    int direction,
                    const void* params)
{
    return mode->init(state,
                      cipher, cipher_state,
                      iv, iv_len,
                      direction,
                      params);
}

void block_mode_update(const struct BLOCK_MODE *mode,
                       void *state,
                       const struct BLOCK_CIPHER *cipher,
                       void* cipher_state,
                       const void* in,
                       size_t inlen,
                       void* out,
                       size_t* outlen)
{
    mode->update(state, cipher, cipher_state, in, inlen, out, outlen);
}

int block_mode_final(const struct BLOCK_MODE *mode,
                     void *state,
                     const struct BLOCK_CIPHER *cipher,
                     void* cipher_state,
                     void* out,
                     size_t* outlen)
{
    return mode->final(state, cipher, cipher_state, out, outlen);
}

void block_mode_free(const struct BLOCK_MODE *mode,
                     void *state,
                     const struct BLOCK_CIPHER *cipher,
                     void* cipher_state)
{
    mode->free(state, cipher, cipher_state);
}

void block_mode_copy(const struct BLOCK_MODE *mode,
                     const struct BLOCK_CIPHER *cipher,
                     void *dst,
                     const void *src)
{
    mode->copy(dst, src, cipher);
}

