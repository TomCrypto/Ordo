#include <primitives/primitives.h>
#include <common/identification.h>
#include <string.h>

#include <primitives/block_ciphers/nullcipher.h>
#include <primitives/block_ciphers/threefish256.h>
#include <primitives/block_ciphers/aes.h>

#include <primitives/stream_ciphers/rc4.h>

#include <primitives/hash_functions/md5.h>
#include <primitives/hash_functions/sha256.h>
#include <primitives/hash_functions/skein256.h>

/******************************************************************************/

/*! \brief Block cipher object.
 *
 * This represents a block cipher object. */
struct BLOCK_CIPHER
{
    size_t block_size;
    BLOCK_ALLOC alloc;
    BLOCK_INIT init;
    BLOCK_UPDATE forward;
    BLOCK_UPDATE inverse;
    BLOCK_FREE free;
    char* name;
};

/*! \brief Stream cipher object.
 *
 * This represents a stream cipher object. */
struct STREAM_CIPHER
{
    STREAM_ALLOC alloc;
    STREAM_INIT init;
    STREAM_UPDATE update;
    STREAM_FREE free;
    char* name;
};

/*! \brief Hash function object.
 *
 * This represents a hash function object. */
struct HASH_FUNCTION
{
    size_t digest_length;
    size_t block_size;
    HASH_ALLOC alloc;
    HASH_INIT init;
    HASH_UPDATE update;
    HASH_FINAL final;
    HASH_FREE free;
    HASH_COPY copy;
    char* name;
};

void make_block_cipher(struct BLOCK_CIPHER *primitive, size_t block_size,
                       BLOCK_ALLOC alloc, BLOCK_INIT init, BLOCK_UPDATE forward,
                       BLOCK_UPDATE inverse, BLOCK_FREE free, char *name)
{
    primitive->block_size = block_size;
    primitive->alloc   = alloc;
    primitive->init    = init;
    primitive->forward = forward;
    primitive->inverse = inverse;
    primitive->free    = free;
    primitive->name    = name;
}

void make_stream_cipher(struct STREAM_CIPHER *primitive,
                       STREAM_ALLOC alloc, STREAM_INIT init, STREAM_UPDATE update,
                       STREAM_FREE free, char *name)
{
    primitive->alloc   = alloc;
    primitive->init    = init;
    primitive->update  = update;
    primitive->free    = free;
    primitive->name    = name;
}

void make_hash_function(struct HASH_FUNCTION *primitive, size_t digest_length, size_t block_size,
                       HASH_ALLOC alloc, HASH_INIT init, HASH_UPDATE update,
                       HASH_FINAL final, HASH_FREE free, HASH_COPY copy, char *name)
{
    primitive->digest_length = digest_length;
    primitive->block_size = block_size;
    primitive->alloc   = alloc;
    primitive->init    = init;
    primitive->update  = update;
    primitive->final   = final;
    primitive->free    = free;
    primitive->copy    = copy;
    primitive->name    = name;
}

const char* block_cipher_name(struct BLOCK_CIPHER *primitive)
{
	return primitive->name;
}

const char* stream_cipher_name(struct STREAM_CIPHER *primitive)
{
	return primitive->name;
}

const char* hash_function_name(struct HASH_FUNCTION *primitive)
{
	return primitive->name;
}

size_t cipher_block_size(struct BLOCK_CIPHER *primitive)
{
	return primitive->block_size;
}

size_t hash_digest_length(struct HASH_FUNCTION *primitive)
{
	return primitive->digest_length;
}

size_t hash_block_size(struct HASH_FUNCTION *primitive)
{
	return primitive->block_size;
}

/* Primitive lists. */
struct BLOCK_CIPHER block[BLOCK_COUNT];
struct STREAM_CIPHER stream[STREAM_COUNT];
struct HASH_FUNCTION hash[HASH_COUNT];

/* Loads all primitives. */
void load_primitives()
{
    /* Block cipher primitives. */
    nullcipher_set_primitive  (&block[BLOCK_NULLCIPHER]);
    threefish256_set_primitive(&block[BLOCK_THREEFISH256]);
    aes_set_primitive         (&block[BLOCK_AES]);

    /* Stream cipher primitives. */
    rc4_set_primitive(&stream[STREAM_RC4]);

    /* Hash primitives. */
    sha256_set_primitive(&hash[HASH_SHA256]);
    md5_set_primitive(&hash[HASH_MD5]);
    skein256_set_primitive(&hash[HASH_SKEIN256]);
}

/* Pass-through functions to acquire primitives. */
struct BLOCK_CIPHER* NullCipher()   { return &block[BLOCK_NULLCIPHER]; }
struct BLOCK_CIPHER* Threefish256() { return &block[BLOCK_THREEFISH256]; }
struct BLOCK_CIPHER* AES()          { return &block[BLOCK_AES]; }

struct STREAM_CIPHER* RC4() { return &stream[STREAM_RC4]; }

struct HASH_FUNCTION* SHA256() { return &hash[HASH_SHA256]; }
struct HASH_FUNCTION* MD5() { return &hash[HASH_MD5]; }
struct HASH_FUNCTION* Skein256() { return &hash[HASH_SKEIN256]; }

/* Returns a block cipher primitive object from a name. */
struct BLOCK_CIPHER* block_cipher_by_name(char* name)
{
    int t;
    for (t = 0; t < BLOCK_COUNT; t++)
    {
        /* Simply compare against the cipher list. */
        if (!strncmp(name, block[t].name, strlen(block[t].name)))
            return &block[t];
    }

    /* No match found. */
    return 0;
}

/* Returns a block cipher primitive object from an ID. */
struct BLOCK_CIPHER* block_cipher_by_id(size_t id)
{
    return (id < BLOCK_COUNT) ? &block[id] : 0;
}

/* Returns a stream cipher primitive object from a name. */
struct STREAM_CIPHER* stream_cipher_by_name(char* name)
{
    int t;
    for (t = 0; t < STREAM_COUNT; t++)
    {
        /* Simply compare against the cipher list. */
        if (!strncmp(name, stream[t].name, strlen(stream[t].name)))
            return &stream[t];
    }

    /* No match found. */
    return 0;
}

/* Returns a stream cipher primitive object from an ID. */
struct STREAM_CIPHER* stream_cipher_by_id(size_t id)
{
    return (id < STREAM_COUNT) ? &stream[id] : 0;
}

/* Returns a hash function primitive object from a name. */
struct HASH_FUNCTION* hash_function_by_name(char* name)
{
    int t;
    for (t = 0; t < HASH_COUNT; t++)
    {
        /* Simply compare against the cipher list. */
        if (!strncmp(name, hash[t].name, strlen(hash[t].name)))
            return &hash[t];
    }

    /* No match found. */
    return 0;
}

/* Returns a hash function primitive object from an ID. */
struct HASH_FUNCTION* hash_function_by_id(size_t id)
{
    return (id < HASH_COUNT) ? &hash[id] : 0;
}



/**********************************************************
**********************************************************/



/* BLOCK CIPHER ABSTRACTION LAYER. */
void* block_cipher_alloc(struct BLOCK_CIPHER* primitive)
{
	return primitive->alloc();
}

int block_cipher_init(struct BLOCK_CIPHER* primitive, void *ctx, void *key, size_t key_size, void *params)
{
	return primitive->init(ctx, key, key_size, params);
}

void block_cipher_forward(struct BLOCK_CIPHER* primitive, void *ctx, void *block)
{
	primitive->forward(ctx, block);
}

void block_cipher_inverse(struct BLOCK_CIPHER* primitive, void *ctx, void *block)
{
	primitive->inverse(ctx, block);
}

void block_cipher_free(struct BLOCK_CIPHER* primitive, void *ctx)
{
	primitive->free(ctx);
}

/* STREAM CIPHER ABSTRACTION LAYER. */

void* stream_cipher_alloc(struct STREAM_CIPHER *primitive)
{
    return primitive->alloc();
}

int stream_cipher_init(struct STREAM_CIPHER *primitive, void* ctx, void *key, size_t key_size, void *params)
{
    return primitive->init(ctx, key, key_size, params);
}

void stream_cipher_update(struct STREAM_CIPHER *primitive, void* ctx, void *buffer, size_t size)
{
	primitive->update(ctx, buffer, size);
}

void stream_cipher_free(struct STREAM_CIPHER *primitive, void *ctx)
{
    primitive->free(ctx);
}

/* HASH FUNCTION ABSTRACTION LAYER. */

void* hash_function_alloc(struct HASH_FUNCTION *primitive)
{
	return primitive->alloc();
}

int hash_function_init(struct HASH_FUNCTION *primitive, void *ctx, void *params)
{
	return primitive->init(ctx, params);
}

void hash_function_update(struct HASH_FUNCTION *primitive, void *ctx, void *buffer, size_t size)
{
	primitive->update(ctx, buffer, size);
}

void hash_function_final(struct HASH_FUNCTION *primitive, void *ctx, void *digest)
{
	primitive->final(ctx, digest);
}

void hash_function_free(struct HASH_FUNCTION *primitive, void *ctx)
{
	primitive->free(ctx);
}

void hash_function_copy(struct HASH_FUNCTION *primitive, void *dst, void *src)
{
	primitive->copy(dst, src);
}
