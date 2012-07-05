#ifndef ordotypes_h
#define ordotypes_h

/* Standard includes. */
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

/* Library dependencies. */
#include "securemem.h"
#include "environment.h"

/* Yes, well, stdbool.h doesn't exist under VS2010 for some reason. */
typedef int bool;
#define false 0
#define true 1

#endif