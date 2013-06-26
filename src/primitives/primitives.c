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

struct BLOCK_CIPHER
{
    size_t block_size;
    BLOCK_ALLOC alloc;
    BLOCK_INIT init;
    BLOCK_UPDATE forward;
    BLOCK_UPDATE inverse;
    BLOCK_FREE free;
    BLOCK_COPY copy;
    BLOCK_KEYLEN keylen;
    const char* name;
};

struct STREAM_CIPHER
{
    STREAM_ALLOC alloc;
    STREAM_INIT init;
    STREAM_UPDATE update;
    STREAM_FREE free;
    STREAM_COPY copy;
    STREAM_KEYLEN keylen;
    const char* name;
};

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
    const char* name;
};

void make_block_cipher(struct BLOCK_CIPHER *primitive,
                       size_t block_size,
                       BLOCK_ALLOC alloc,
                       BLOCK_INIT init,
                       BLOCK_UPDATE forward,
                       BLOCK_UPDATE inverse,
                       BLOCK_FREE free,
                       BLOCK_COPY copy,
                       BLOCK_KEYLEN keylen,
                       const char *name)
{
    primitive->block_size = block_size;
    primitive->alloc   = alloc;
    primitive->init    = init;
    primitive->forward = forward;
    primitive->inverse = inverse;
    primitive->free    = free;
    primitive->copy    = copy;
    primitive->keylen  = keylen;
    primitive->name    = name;
}

void make_stream_cipher(struct STREAM_CIPHER *primitive,
                        STREAM_ALLOC alloc,
                        STREAM_INIT init,
                        STREAM_UPDATE update,
                        STREAM_FREE free,
                        STREAM_COPY copy,
                        STREAM_KEYLEN keylen,
                        const char *name)
{
    primitive->alloc   = alloc;
    primitive->init    = init;
    primitive->update  = update;
    primitive->free    = free;
    primitive->copy    = copy;
    primitive->keylen  = keylen;
    primitive->name    = name;
}

void make_hash_function(struct HASH_FUNCTION *primitive,
                        size_t digest_length,
                        size_t block_size,
                        HASH_ALLOC alloc,
                        HASH_INIT init,
                        HASH_UPDATE update,
                        HASH_FINAL final,
                        HASH_FREE free,
                        HASH_COPY copy,
                        const char *name)
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

/******************************************************************************/

const char* block_cipher_name(const struct BLOCK_CIPHER *primitive)
{
    return primitive->name;
}

const char* stream_cipher_name(const struct STREAM_CIPHER *primitive)
{
    return primitive->name;
}

const char* hash_function_name(const struct HASH_FUNCTION *primitive)
{
    return primitive->name;
}

size_t cipher_block_size(const struct BLOCK_CIPHER *primitive)
{
    return primitive->block_size;
}

size_t hash_digest_length(const struct HASH_FUNCTION *primitive)
{
    return primitive->digest_length;
}

size_t hash_block_size(const struct HASH_FUNCTION *primitive)
{
    return primitive->block_size;
}

/******************************************************************************/

struct BLOCK_CIPHER block[BLOCK_COUNT];
struct STREAM_CIPHER stream[STREAM_COUNT];
struct HASH_FUNCTION hash[HASH_COUNT];

void load_primitives()
{
    nullcipher_set_primitive(&block[BLOCK_NULLCIPHER]);
    threefish256_set_primitive(&block[BLOCK_THREEFISH256]);
    aes_set_primitive(&block[BLOCK_AES]);

    rc4_set_primitive(&stream[STREAM_RC4]);

    sha256_set_primitive(&hash[HASH_SHA256]);
    md5_set_primitive(&hash[HASH_MD5]);
    skein256_set_primitive(&hash[HASH_SKEIN256]);
}

const struct BLOCK_CIPHER* NullCipher()
{
    return &block[BLOCK_NULLCIPHER];
}

const struct BLOCK_CIPHER* Threefish256()
{
    return &block[BLOCK_THREEFISH256];
}

const struct BLOCK_CIPHER* AES()
{
    return &block[BLOCK_AES];
}

const struct STREAM_CIPHER* RC4()
{
    return &stream[STREAM_RC4];
}

const struct HASH_FUNCTION* SHA256()
{
    return &hash[HASH_SHA256];
}

const struct HASH_FUNCTION* MD5()
{
    return &hash[HASH_MD5];
}

const struct HASH_FUNCTION* Skein256()
{
    return &hash[HASH_SKEIN256];
}

/******************************************************************************/

const struct BLOCK_CIPHER* block_cipher_by_name(const char *name)
{
    ssize_t t;

    for (t = 0; t < BLOCK_COUNT; t++)
    {
        if (!strncmp(name, block[t].name, strlen(block[t].name)))
            return &block[t];
    }

    return 0;
}

const struct STREAM_CIPHER* stream_cipher_by_name(const char *name)
{
    ssize_t t;

    for (t = 0; t < STREAM_COUNT; t++)
    {
        if (!strncmp(name, stream[t].name, strlen(stream[t].name)))
            return &stream[t];
    }

    return 0;
}

const struct HASH_FUNCTION* hash_function_by_name(const char *name)
{
    ssize_t t;

    for (t = 0; t < HASH_COUNT; t++)
    {
        if (!strncmp(name, hash[t].name, strlen(hash[t].name)))
            return &hash[t];
    }

    return 0;
}

const struct BLOCK_CIPHER* block_cipher_by_id(size_t id)
{
    return (id < BLOCK_COUNT) ? &block[id] : 0;
}

const struct STREAM_CIPHER* stream_cipher_by_id(size_t id)
{
    return (id < STREAM_COUNT) ? &stream[id] : 0;
}

const struct HASH_FUNCTION* hash_function_by_id(size_t id)
{
    return (id < HASH_COUNT) ? &hash[id] : 0;
}

/******************************************************************************/

void* block_cipher_alloc(const struct BLOCK_CIPHER *primitive)
{
    return primitive->alloc();
}

int block_cipher_init(const struct BLOCK_CIPHER *primitive,
                      void *state,
                      const void *key,
                      size_t key_size,
                      const void *params)
{
    return primitive->init(state, key, key_size, params);
}

void block_cipher_forward(const struct BLOCK_CIPHER *primitive,
                          void *state,
                          void *block)
{
    primitive->forward(state, block);
}

void block_cipher_inverse(const struct BLOCK_CIPHER *primitive,
                          void *state,
                          void *block)
{
    primitive->inverse(state, block);
}

void block_cipher_free(const struct BLOCK_CIPHER *primitive,
                       void *state)
{
    primitive->free(state);
}

void block_cipher_copy(const struct BLOCK_CIPHER *primitive,
                       void *dst,
                       const void *src)
{
    primitive->copy(dst, src);
}

size_t block_cipher_key_len(const struct BLOCK_CIPHER *primitive,
                            size_t key_len)
{
    return primitive->keylen(key_len);
}

void* stream_cipher_alloc(const struct STREAM_CIPHER *primitive)
{
    return primitive->alloc();
}

int stream_cipher_init(const struct STREAM_CIPHER *primitive,
                       void* state,
                       const void *key,
                       size_t key_size,
                       const void *params)
{
    return primitive->init(state, key, key_size, params);
}

void stream_cipher_update(const struct STREAM_CIPHER *primitive,
                          void* state,
                          void *buffer,
                          size_t size)
{
    primitive->update(state, buffer, size);
}

void stream_cipher_free(const struct STREAM_CIPHER *primitive,
                        void *state)
{
    primitive->free(state);
}

void stream_cipher_copy(const struct STREAM_CIPHER *primitive,
                        void *dst,
                        const void *src)
{
    primitive->copy(dst, src);
}

size_t stream_cipher_key_len(const struct STREAM_CIPHER *primitive,
                             size_t key_len)
{
    return primitive->keylen(key_len);
}

void* hash_function_alloc(const struct HASH_FUNCTION *primitive)
{
    return primitive->alloc();
}

int hash_function_init(const struct HASH_FUNCTION *primitive,
                       void *state,
                       const void *params)
{
    return primitive->init(state, params);
}

void hash_function_update(const struct HASH_FUNCTION *primitive,
                          void *state,
                          const void *buffer,
                          size_t size)
{
    primitive->update(state, buffer, size);
}

void hash_function_final(const struct HASH_FUNCTION *primitive,
                         void *state,
                         void *digest)
{
    primitive->final(state, digest);
}

void hash_function_free(const struct HASH_FUNCTION *primitive,
                        void *state)
{
    primitive->free(state);
}

void hash_function_copy(const struct HASH_FUNCTION *primitive,
                        void *dst,
                        const void *src)
{
    primitive->copy(dst, src);
}

