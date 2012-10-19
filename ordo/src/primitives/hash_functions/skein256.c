#include <primitives/hash_functions/skein256.h>

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
typedef struct SKEIN256_STATE
{
    uint64_t state[4];
    uint64_t block[4];
    uint64_t blockLength;
    uint64_t messageLength;
    uint64_t outputLength;
} SKEIN256_STATE;

/* Shorthand macro for context casting. */
#define state(x) ((SKEIN256_STATE*)(x->ctx))

HASH_FUNCTION_CONTEXT* Skein256_Create()
{
    /* Allocate memory for the Skein-256 state. */
    HASH_FUNCTION_CONTEXT* ctx = salloc(sizeof(HASH_FUNCTION_CONTEXT));
    if (ctx)
    {
        if ((ctx->ctx = salloc(sizeof(SKEIN256_STATE)))) return ctx;
        sfree(ctx, sizeof(HASH_FUNCTION_CONTEXT));
    }

    /* Allocation failed. */
    return 0;
}

/* This is the Skein-256 compression function. */
inline void Skein256_Compress(uint64_t block[4], uint64_t state[4], uint64_t tweak[2])
{
    /* Some variables. */
    UINT256_64 subkeys[19];

    /* Perform the key schedule with the tweak. */
    Threefish256_KeySchedule((UINT256_64*)state, tweak, subkeys);

    /* Save the input block. */
    memcpy(state, block, SKEIN256_INTERNAL);

    /* Encrypt the block with this key. */
    Threefish256_Forward_Raw((UINT256_64*)state, subkeys);

    /* Feed-forward to create the new state. */
    xorBuffer((unsigned char*)state, (unsigned char*)block, SKEIN256_INTERNAL);
}

int Skein256_Init(HASH_FUNCTION_CONTEXT* ctx, SKEIN256_PARAMS* params)
{
    /* Some variables. */
    uint64_t tweak[2];

    /* Initialize context fields. */
    state(ctx)->blockLength = 0;
    state(ctx)->messageLength = 0;

    /* If parameters have been passed, process them into a configuration block. */
    if (params)
    {
        /* Save the desired digest's output length (in bytes). */
        state(ctx)->outputLength = params->outputLength / 8;

        /* Generate the initial state from the configuration block. */
        memset(state(ctx)->state, 0, SKEIN256_BLOCK);
        memcpy(state(ctx)->block, params, SKEIN256_BLOCK);
        MAKETWEAK(tweak, SKEIN_UBI_CFG, SKEIN256_BLOCK, 1, 1);
        Skein256_Compress(state(ctx)->block, state(ctx)->state, tweak);
    }
    else
    {
        /* Otherwise, assume default parameters and implicitly process the default configuration block. */
        memcpy(state(ctx)->state, Skein256_initialState, SKEIN256_INTERNAL);
        state(ctx)->outputLength = SKEIN256_INTERNAL;
    }

    /* We're done! */
    return ORDO_ESUCCESS;
}

void Skein256_Update(HASH_FUNCTION_CONTEXT* ctx, void* buffer, size_t size)
{
    /* Some variables. */
    uint64_t tweak[2];
    size_t pad = 0;

    /* Is the message provided long enough to complete a block? */
    if (state(ctx)->blockLength + size > SKEIN256_BLOCK)
    {
        /* Compute how much of the message is needed to complete the block. */
        pad = SKEIN256_BLOCK - state(ctx)->blockLength;
        memcpy(((unsigned char*)state(ctx)->block) + state(ctx)->blockLength, buffer, pad);
        state(ctx)->messageLength += pad;

        /* Generate the tweak for this block. */
        MAKETWEAK(tweak, SKEIN_UBI_MSG, state(ctx)->messageLength, state(ctx)->messageLength <= SKEIN256_BLOCK, 0);

        /* We now have a complete block which we can process. */
        Skein256_Compress(state(ctx)->block, state(ctx)->state, tweak);
        state(ctx)->blockLength = 0;

        /* Offset the message accordingly. */
        buffer = (unsigned char*)buffer + pad;
        size -= pad;

        /* At this point, the block is empty, so process complete blocks directly except the last one. */
        while (size > SKEIN256_BLOCK)
        {
            /* Just process this block. */
            state(ctx)->messageLength += SKEIN256_BLOCK;
            memcpy(state(ctx)->block, buffer, SKEIN256_BLOCK);
            MAKETWEAK(tweak, SKEIN_UBI_MSG, state(ctx)->messageLength, state(ctx)->messageLength <= SKEIN256_BLOCK, 0);
            Skein256_Compress(state(ctx)->block, state(ctx)->state, tweak);
            buffer = (unsigned char*)buffer + SKEIN256_BLOCK;
            size -= SKEIN256_BLOCK;
        }
    }

    /* If we have anything left over, just append it to the context's block field. */
    memcpy(((unsigned char*)state(ctx)->block) + state(ctx)->blockLength, buffer, size);
    state(ctx)->blockLength += size;
}

void Skein256_Final(HASH_FUNCTION_CONTEXT* ctx, void* digest)
{
    /* Some variables. */
    uint64_t tweak[2];
    uint64_t ctr = 0;
    uint64_t lst[4];

    /* At this point, we must have data left (possibly a full block), process it. First wipe any residual old data. */
    memset(((unsigned char*)state(ctx)->block) + state(ctx)->blockLength, 0, SKEIN256_BLOCK - state(ctx)->blockLength);

    /* Then, just process this final message block. */
    state(ctx)->messageLength += state(ctx)->blockLength;
    MAKETWEAK(tweak, SKEIN_UBI_MSG, state(ctx)->messageLength, state(ctx)->messageLength <= SKEIN256_BLOCK, 1);
    Skein256_Compress(state(ctx)->block, state(ctx)->state, tweak);

    /* Wipe the context's data block for output. */
    memset(state(ctx)->block, 0, SKEIN256_BLOCK);

    /* We're done, output the final state as the digest, iterated as needed to match the desired output length. */
    while (state(ctx)->outputLength != 0)
    {
        /* Copy the current internal state since it is reused for all output iterations. */
        memcpy(lst, state(ctx)->state, SKEIN256_INTERNAL);

        /* Process this output block. */
        state(ctx)->block[0] = ctr++;
        MAKETWEAK(tweak, SKEIN_UBI_OUT, sizeof(uint64_t), 1, 1);
        Skein256_Compress(state(ctx)->block, lst, tweak);

        /* Copy it into the user digest. */
        memcpy((unsigned char*)digest + (ctr - 1) * SKEIN256_BLOCK, lst, min(state(ctx)->outputLength, SKEIN256_BLOCK));
        state(ctx)->outputLength -= min(state(ctx)->outputLength, SKEIN256_BLOCK);
    }
}

void Skein256_Free(HASH_FUNCTION_CONTEXT* ctx)
{
    /* Free memory for the Skein-256 state. */
    sfree(ctx->ctx, sizeof(SKEIN256_STATE));
    sfree(ctx, sizeof(HASH_FUNCTION_CONTEXT));
}

/* Fills a HASH_FUNCTION struct with the correct information. */
void Skein256_SetPrimitive(HASH_FUNCTION* hash)
{
    MAKE_HASH_FUNCTION(hash, SKEIN256_INTERNAL, SKEIN256_BLOCK, Skein256_Create, Skein256_Init, Skein256_Update, Skein256_Final, Skein256_Free, "Skein-256");
}

