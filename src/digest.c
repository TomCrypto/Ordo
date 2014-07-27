/*===-- digest.c --------------------------------------*- generic -*- C -*-===*/

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

#include "ordo/digest/digest.h"

/*===----------------------------------------------------------------------===*/

#ifdef OPAQUE
#define DIGEST_CTX HASH_STATE
#endif
