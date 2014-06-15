/*===-- primitives/stream_ciphers/stream_params.h ------*- PUBLIC -*- H -*-===*/
/**
*** @file
*** @brief Primitive Parameters
***
*** This header contains parameter structures for all stream ciphers.
**/
/*===----------------------------------------------------------------------===*/

#ifndef ORDO_STREAM_PARAMS_H
#define ORDO_STREAM_PARAMS_H

/** @cond **/
#include "ordo/common/interface.h"
/** @endcond **/

#ifdef __cplusplus
extern "C" {
#endif

/*===----------------------------------------------------------------------===*/

/** @brief RC4 stream cipher parameters.
**/
struct RC4_PARAMS
{
    /** The number of keystream bytes to drop prior to encryption.
    ***
    *** @remarks Setting this implements the given RC4-drop variant.
    ***
    *** @remarks If this \c RC4_PARAMS  structure is \b not  passed to the RC4
    ***          stream cipher primitive, the default drop amount is 2048.
    **/
    size_t drop;
};

/*===----------------------------------------------------------------------===*/

#ifdef __cplusplus
}
#endif

#endif
