/*===-- enc/block_modes/mode_params.h -----------------*- PUBLIC -*- H -*-===*/
/**
*** @file
*** @brief Primitive Parameters
***
*** This header contains parameter structures for all block modes.
**/
/*===----------------------------------------------------------------------===*/

#ifndef ORDO_MODE_PARAMS_H
#define ORDO_MODE_PARAMS_H

/** @cond **/
#include "ordo/common/interface.h"
/** @endcond **/

#ifdef __cplusplus
extern "C" {
#endif

/*===----------------------------------------------------------------------===*/

/** @brief ECB parameters.
**/
struct ECB_PARAMS
{
    /** Whether padding should be used.
    ***
    *** @remarks Set to 0 to disable padding, and 1 to enable it.
    ***
    *** @remarks Padding is enabled by default if parameters are not used.
    **/
    int padding;
};

/** @brief CBC parameters.
**/
struct CBC_PARAMS
{
    /** Whether padding should be used.
    ***
    *** @remarks Set to 0 to disable padding, and 1 to enable it.
    ***
    *** @remarks Padding is enabled by default if parameters are not used.
    **/
    int padding;
};

/** @brief Polymorphic block mode parameter union.
**/
union BLOCK_MODE_PARAMS
{
    struct ECB_PARAMS                    ecb;
    struct CBC_PARAMS                    cbc;
};

/*===----------------------------------------------------------------------===*/

#ifdef __cplusplus
}
#endif

#endif
