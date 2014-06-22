/*===-- utils.c ---------------------------------------*- generic -*- C -*-===*/

#include "ordo/misc/utils.h"

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

/*===----------------------------------------------------------------------===*/

int ctcmp(const void *x, const void *y, size_t len)
{
    const uint8_t *px = x;
    const uint8_t *py = y;
    unsigned char acc = 0;

    while (len--)
        acc |= *(px++) ^ *(py++);

    return acc == 0;
}
