/**
 * @file ordotypes.h
 * Contains various library-wide definitions and includes.
 *
 * \todo Improve code related to error handling. *
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

// these error codes are so awful, wtf..

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

/* Checks whether the next padding bytes at buffer all have the correct padding value. */
int padcheck(unsigned char* buffer, unsigned char padding);

/* Xors two buffers together. */
void XOR(unsigned char* val, unsigned char* mod, size_t len);

/* Increments a counter of arbitrary size as if it were a len-byte integer
   Propagation is done from left-to-right in memory storage order. */
void incCounter(unsigned char* iv, size_t len);

#endif
