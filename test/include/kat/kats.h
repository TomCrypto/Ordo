#ifndef KAT_KATS_H
#define KAT_KATS_H

#include "kat/parser.h"

static struct KAT_RECORD kats[] =
{
    {
        .name = "RC4",
        .type = KAT_STREAM,
        .key = "\x01\x02\x03\x04\x05",
        .key_len = 5,
        .plaintext = "\x01\x23\x45\x67\x89\xab\xcd\xef",
        .pt_len = 8,
        .ciphertext = "\xcd\x7b\x6a\xec\x20\x59\xa8\x0d",
        .ct_len = 8,
    },
};

#endif
