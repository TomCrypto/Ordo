#include <primitives/primitives.h>
#include <primitives/ciphers/rc4.h>

/* A structure containing an RC4 state. */
#if ENVIRONMENT_64
typedef struct RC4_STATE
{
    uint64_t i;
    uint64_t j;
    uint64_t s[256];
} RC4_STATE;
#else
typedef struct RC4_STATE
{
    uint8_t s[256];
    uint8_t i;
    uint8_t j;
} RC4_STATE;
#endif

/* Shorthand macro for context casting. */
#define state(x) ((RC4_STATE*)(x->cipher))

/* Swaps two bytes. */
void swapByte(uint8_t* a, uint8_t* b)
{
    uint8_t c;
    c = *a;
    *a = *b;
    *b = c;
}

CIPHER_PRIMITIVE_CONTEXT* RC4_Create(CIPHER_PRIMITIVE* primitive)
{
    /* Allocate memory for the RC4 state. */
    CIPHER_PRIMITIVE_CONTEXT* ctx = salloc(sizeof(CIPHER_PRIMITIVE_CONTEXT));
    if (ctx)
    {
        ctx->primitive = primitive;
        if ((ctx->cipher = salloc(sizeof(RC4_STATE)))) return ctx;
        sfree(ctx, sizeof(CIPHER_PRIMITIVE_CONTEXT));
    }

    /* Allocation failed. */
    return 0;
}

int RC4_Init(CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* key, size_t keySize, RC4_PARAMS* params)
{
    /* Loop variables. */
    size_t t, drop;
    uint8_t tmp;

    /* Allowed keys are 40-2048 bits long. */
    if ((keySize < 5) || (keySize > 256)) return ORDO_EKEYSIZE;

    /* Initialize the permutation array. */
    for (t = 0; t < 256; t++) state(cipher)->s[t] = t;

    /* Mix the key into the RC4 state. */
    state(cipher)->j = 0;
    for (t = 0; t < 256; t++)
    {
        /* Update state pointer. */
        state(cipher)->j = (state(cipher)->j + state(cipher)->s[t] + key[t % keySize]) & 0xFF;

        /* Swap. */
        tmp = state(cipher)->s[t];
        state(cipher)->s[t] = state(cipher)->s[state(cipher)->j];
        state(cipher)->s[state(cipher)->j] = tmp;
    }

    /* Reset the state pointers. */
    state(cipher)->i = 0;
    state(cipher)->j = 0;

    /* Calculate the amount of bytes to drop (default is 2048). */
    drop = (params == 0) ? 2048 : params->drop;

    /* Throw away the first drop bytes. */
    for (t = 0; t < drop; t++) RC4_Update(cipher, &tmp, 1);

    /* Return success. */
    return ORDO_ESUCCESS;
}

void RC4_Update(CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* block, size_t len)
{
    #if ENVIRONMENT_64
    /* Fast 64-bit implementation (note in 64-bit mode, len is a 64-bit unsigned integer). */
    RC4_Update_ASM(state(cipher), len, block, block);
    #else
    /* Loop variable. */
    RC4_STATE state = *(RC4_STATE*)cipher->cipher;
    size_t t = 0;

    /* Iterate over each byte and xor the keystream with the plaintext. */
    while (t != len)
    {
        state.j += state.s[++state.i];
        swapByte(&state.s[state.i], &state.s[state.j]);
        block[t++] ^= state.s[(state.s[state.i] + state.s[state.j]) & 0xFF];
    }

    /* Copy the state back in. */
    *(RC4_STATE*)cipher->cipher = state;
    #endif
}

void RC4_Free(CIPHER_PRIMITIVE_CONTEXT* cipher)
{
    /* Free memory for the RC4 state. */
    sfree(cipher->cipher, sizeof(RC4_STATE));
    sfree(cipher, sizeof(CIPHER_PRIMITIVE_CONTEXT));
}

/* Fills a CIPHER_PRIMITIVE struct with the correct information. */
void RC4_SetPrimitive(CIPHER_PRIMITIVE* primitive)
{
    PRIMITIVE_MAKECIPHER(primitive, 0, RC4_Create, RC4_Init, RC4_Update, 0, RC4_Free, "RC4");
}
