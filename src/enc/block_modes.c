#include <enc/block_modes.h>

#include <common/identification.h>
#include <common/ordo_errors.h>
#include <common/secure_mem.h>

#include <enc/block_cipher_modes/ecb.h>
#include <enc/block_cipher_modes/cbc.h>
#include <enc/block_cipher_modes/ctr.h>
#include <enc/block_cipher_modes/cfb.h>
#include <enc/block_cipher_modes/ofb.h>

/******************************************************************************/

/*! \brief Block cipher mode of operation object.
 *
 * This represents a block cipher mode of operation object. */
struct BLOCK_MODE
{
    BLOCK_MODE_ALLOC alloc;
    BLOCK_MODE_INIT init;
    BLOCK_MODE_UPDATE update;
    BLOCK_MODE_FINAL final;
    BLOCK_MODE_FREE free;
    char* name;
};

/* Block cipher mode of operation list. */
struct BLOCK_MODE encryptModes[BLOCK_MODE_COUNT];

/* Loads all block cipher modes. */
void encryptLoad()
{
    /* Initialize each block cipher mode object. */
    ecb_set_mode   (&encryptModes[BLOCK_MODE_ECB]);
    cbc_set_mode   (&encryptModes[BLOCK_MODE_CBC]);
    ctr_set_mode   (&encryptModes[BLOCK_MODE_CTR]);
    cfb_set_mode   (&encryptModes[BLOCK_MODE_CFB]);
    ofb_set_mode   (&encryptModes[BLOCK_MODE_OFB]);
}

/* Pass-through functions to acquire modes of operation. */
struct BLOCK_MODE* ECB()    { return &encryptModes[BLOCK_MODE_ECB]; }
struct BLOCK_MODE* CBC()    { return &encryptModes[BLOCK_MODE_CBC]; }
struct BLOCK_MODE* CTR()    { return &encryptModes[BLOCK_MODE_CTR]; }
struct BLOCK_MODE* CFB()    { return &encryptModes[BLOCK_MODE_CFB]; }
struct BLOCK_MODE* OFB()    { return &encryptModes[BLOCK_MODE_OFB]; }

/* Gets a mode of operation object from a name. */
struct BLOCK_MODE* block_mode_by_name(char* name)
{
    int t;
    for (t = 0; t < BLOCK_MODE_COUNT; t++)
    {
        /* Simply compare against the mode of operation list. */
        if (strcmp(name, encryptModes[t].name) == 0) return &encryptModes[t];
    }

    /* No match found. */
    return 0;
}

/* Returns a block cipher mode object from an ID. */
struct BLOCK_MODE* block_mode_by_id(size_t id)
{
    return (id < BLOCK_MODE_COUNT) ? &encryptModes[id] : 0;
}

const char* block_mode_name(struct BLOCK_MODE *mode)
{
    return mode->name;
}

void make_block_mode(struct BLOCK_MODE *mode,
                       BLOCK_MODE_ALLOC alloc, BLOCK_MODE_INIT init, BLOCK_MODE_UPDATE update,
                       BLOCK_MODE_FINAL final, BLOCK_MODE_FREE free, char *name)
{
    mode->alloc = alloc;
    mode->init = init;
    mode->update = update;
    mode->final = final;
    mode->free = free;
    mode->name = name;
}



/**********************************************************
**********************************************************/



/* BLOCK MODE ABSTRACTION LAYER. */

void* block_mode_alloc(struct BLOCK_MODE* mode, struct BLOCK_CIPHER *cipher, void* cipher_ctx)
{
    return mode->alloc(cipher, cipher_ctx);
}

int block_mode_init(struct BLOCK_MODE *mode, void *ctx, struct BLOCK_CIPHER *cipher, void* cipher_ctx,
                        void* iv, int dir, void* params)
{
    return mode->init(ctx, cipher, cipher_ctx, iv, dir ,params);
}

void block_mode_update(struct BLOCK_MODE *mode, void *ctx, struct BLOCK_CIPHER *cipher, void* cipher_ctx,
                           void* in, size_t inlen,
                           void* out, size_t* outlen)
{
    mode->update(ctx, cipher, cipher_ctx, in, inlen, out, outlen);
}

int block_mode_final(struct BLOCK_MODE *mode, void *ctx, struct BLOCK_CIPHER *cipher, void* cipher_ctx,
                         void* out, size_t* outlen)
{
    return mode->final(ctx, cipher, cipher_ctx, out, outlen);
}

void block_mode_free(struct BLOCK_MODE *mode, void *ctx, struct BLOCK_CIPHER *cipher, void* cipher_ctx)
{
    mode->free(ctx, cipher, cipher_ctx);
}
