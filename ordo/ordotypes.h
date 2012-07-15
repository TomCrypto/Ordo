/**
 * @file OrdoTypes.h
 * Contains various library-wide definitions and includes.
 *
 */

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

/*! The function succeeded. */
#define ORDO_ESUCCESS 0

/*! The function failed. */
#define ORDO_EFAIL -1

/*! An unknown error occurred. */
#define ORDO_EUNKNOWN -2

/*! A parameter was incorrect. */
#define ORDO_EPARAM -3

/*! The key size is invalid. */
#define ORDO_EKEYSIZE -4

/*! The context state was invalid. */
#define ORDO_EINVALID -5

/*! The padding was not recognized. */
#define ORDO_EPADDING -6

/*! A resource was unavailable. */
#define ORDO_EUNAVAILABLE -7

#endif
