#include "kat/parser.h"
#include "kat/kats.h"

#include <string.h>

int run_kat(KAT test, enum KAT_TYPE type, const char *name)
{
    size_t t, len = sizeof(kats) / sizeof(struct KAT_RECORD);
    for (t = 0; t < len; ++t)
    {
        struct KAT_RECORD rec = kats[t];
        if (rec.type != type) continue;
        if ((!name) || (name && !strcmp(name, rec.name)))
            if (!test(rec)) return 0;
    }
    
    return 1;
}
