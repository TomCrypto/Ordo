#ifndef KAT_KATS_H
#define KAT_KATS_H

#include "kat/parser.h"

static struct KAT_RECORD kats[] =
{
    {
        "RC4",
        KAT_STREAM,
        "\x01\x02\x03\x04\x05",
        5,
        "\x01\x23\x45\x67\x89\xab\xcd\xef",
        8,
        "\xcd\x7b\x6a\xec\x20\x59\xa8\x0d",
        8,
    },
};

#endif
