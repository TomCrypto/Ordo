#ifndef KAT_PARSER_H
#define KAT_PARSER_H

#include <stdlib.h>

enum KAT_TYPE
{
    KAT_BLOCK,
    KAT_STREAM,
    KAT_HASH,
    KAT_BLOCK_MODE
};

struct KAT_RECORD
{
    const char *name;
    enum KAT_TYPE type;

    const void *key; size_t key_len;
    const void *plaintext; size_t pt_len;
    const void *ciphertext; size_t ct_len;
    const void *digest; size_t digest_len;
};

typedef int (*KAT)(struct KAT_RECORD record);

/* Runs all KATs of a given primitive type, optionally matching by name - this
 * will return 1 if all tests pass, and 0 otherwise. Each KAT is passed to the
 * callback function provided.
*/
int run_kat(KAT test, enum KAT_TYPE type, const char *name);

#endif
