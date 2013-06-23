#include <primitives/hash_functions/skein256.h>

#include <common/ordo_errors.h>
#include <common/secure_mem.h>
#include <common/ordo_utils.h>
#include <string.h>

/******************************************************************************/

/* The Skein-256 internal state size (which is also the default digest size). */
#define SKEIN256_INTERNAL (32)
/* The Skein-256 block size. */
#define SKEIN256_BLOCK (32)

/* Some UBI block type constants. */
#define SKEIN_UBI_CFG 4
#define SKEIN_UBI_MSG 48
#define SKEIN_UBI_OUT 63

/* This creates a UBI-compliant tweak value. */
#define MAKETWEAK(tweak, type, position, first, final) tweak[0] = position; \
                                                       tweak[1] = ((uint64_t)(final) << 63) \
                                                                | ((uint64_t)(first) << 62) \
                                                                | ((uint64_t)(type)  << 56);

/* The Skein-256 initial state vector for the default configuration block. */
const uint64_t Skein256_initialState[4] = {0xFC9DA860D048B449, 0x2FCA66479FA7D833, 0xB33BC3896656840F, 0x6A54E920FDE8DA69};

/* A Skein-256 state. */
struct SKEIN256_STATE
{
    uint64_t state[4];
    uint64_t block[4];
    uint64_t blockLength;
    uint64_t messageLength;
    uint64_t outputLength;
};

struct SKEIN256_STATE* skein256_alloc()
{
    return secure_alloc(sizeof(struct SKEIN256_STATE));
}

/* This is the Skein-256 compression function. */
void skein256Compress(const uint64_t* block, uint64_t* state, uint64_t* tweak)
{
    /* Some variables. */
    uint64_t subkeys[19][4];

    /* Perform the key schedule with the tweak. */
    threefish256_key_schedule(state, tweak, subkeys);

    /* Save the input block. */
    memcpy(state, block, SKEIN256_INTERNAL);

    /* Encrypt the block with this key. */
    threefish256_forward_raw(state, subkeys);

    /* Feed-forward to create the new state. */
    xor_buffer((unsigned char*)state, (unsigned char*)block, SKEIN256_INTERNAL);
}

int skein256_init(struct SKEIN256_STATE *state, const struct SKEIN256_PARAMS* params)
{
    /* Some variables. */
    uint64_t tweak[2];

    /* Initialize context fields. */
    state->blockLength = 0;
    state->messageLength = 0;

    /* If parameters have been passed, process them into a configuration block. */
    if (params)
    {
        /* Save the desired digest's output length (in bytes). */
        state->outputLength = params->outputLength / 8;

        /* Generate the initial state from the configuration block. */
        memset(state->state, 0, SKEIN256_BLOCK);
        memcpy(state->block, params, SKEIN256_BLOCK);
        MAKETWEAK(tweak, SKEIN_UBI_CFG, SKEIN256_BLOCK, 1, 1);
        skein256Compress(state->block, state->state, tweak);
    }
    else
    {
        /* Otherwise, assume default parameters and implicitly process the default configuration block. */
        memcpy(state->state, Skein256_initialState, SKEIN256_INTERNAL);
        state->outputLength = SKEIN256_INTERNAL;
    }

    /* We're done! */
    return ORDO_SUCCESS;
}

void skein256_update(struct SKEIN256_STATE *state, const void* buffer, size_t size)
{
    /* Some variables. */
    uint64_t tweak[2];
    size_t pad = 0;

    /* Is the message provided long enough to complete a block? */
    if (state->blockLength + size > SKEIN256_BLOCK)
    {
        /* Compute how much of the message is needed to complete the block. */
        pad = SKEIN256_BLOCK - state->blockLength;
        memcpy(((unsigned char*)state->block) + state->blockLength, buffer, pad);
        state->messageLength += pad;

        /* Generate the tweak for this block. */
        MAKETWEAK(tweak, SKEIN_UBI_MSG, state->messageLength, state->messageLength <= SKEIN256_BLOCK, 0);

        /* We now have a complete block which we can process. */
        skein256Compress(state->block, state->state, tweak);
        state->blockLength = 0;

        /* Offset the message accordingly. */
        buffer = (unsigned char*)buffer + pad;
        size -= pad;

        /* At this point, the block is empty, so process complete blocks directly except the last one. */
        while (size > SKEIN256_BLOCK)
        {
            /* Just process this block. */
            state->messageLength += SKEIN256_BLOCK;
            memcpy(state->block, buffer, SKEIN256_BLOCK);
            MAKETWEAK(tweak, SKEIN_UBI_MSG, state->messageLength, state->messageLength <= SKEIN256_BLOCK, 0);
            skein256Compress(state->block, state->state, tweak);
            buffer = (unsigned char*)buffer + SKEIN256_BLOCK;
            size -= SKEIN256_BLOCK;
        }
    }

    /* If we have anything left over, just append it to the context's block field. */
    memcpy(((unsigned char*)state->block) + state->blockLength, buffer, size);
    state->blockLength += size;
}

void skein256_final(struct SKEIN256_STATE *state, void* digest)
{
    /* Some variables. */
    uint64_t tweak[2];
    uint64_t ctr = 0;
    uint64_t lst[4];

    /* At this point, we must have data left (possibly a full block), process it. First wipe any residual old data. */
    memset(((unsigned char*)state->block) + state->blockLength, 0, SKEIN256_BLOCK - state->blockLength);

    /* Then, just process this final message block. */
    state->messageLength += state->blockLength;
    MAKETWEAK(tweak, SKEIN_UBI_MSG, state->messageLength, state->messageLength <= SKEIN256_BLOCK, 1);
    skein256Compress(state->block, state->state, tweak);

    /* Wipe the context's data block for output. */
    memset(state->block, 0, SKEIN256_BLOCK);

    /* We're done, output the final state as the digest, iterated as needed to match the desired output length. */
    while (state->outputLength != 0)
    {
        /* Copy the current internal state since it is reused for all output iterations. */
        memcpy(lst, state->state, SKEIN256_INTERNAL);

        /* Process this output block. */
        state->block[0] = ctr++;
        MAKETWEAK(tweak, SKEIN_UBI_OUT, sizeof(uint64_t), 1, 1);
        skein256Compress(state->block, lst, tweak);

        /* Copy it into the user digest. */
        memcpy((unsigned char*)digest + (ctr - 1) * SKEIN256_BLOCK, lst, min(state->outputLength, SKEIN256_BLOCK));
        state->outputLength -= min(state->outputLength, SKEIN256_BLOCK);
    }
}

void skein256_free(struct SKEIN256_STATE *state)
{
    secure_free(state, sizeof(struct SKEIN256_STATE));
}

void skein256_copy(struct SKEIN256_STATE *dst, const struct SKEIN256_STATE *src)
{
    memcpy(dst, src, sizeof(struct SKEIN256_STATE));
}

/* Fills a HASH_FUNCTION struct with the correct information. */
void skein256_set_primitive(struct HASH_FUNCTION* hash)
{
    make_hash_function(hash,
                       SKEIN256_INTERNAL,
                       SKEIN256_BLOCK,
                       (HASH_ALLOC)skein256_alloc,
                       (HASH_INIT)skein256_init,
                       (HASH_UPDATE)skein256_update,
                       (HASH_FINAL)skein256_final,
                       (HASH_FREE)skein256_free,
                       (HASH_COPY)skein256_copy,
                       "Skein-256");
}

