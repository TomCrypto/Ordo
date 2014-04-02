/*===-- enc/block_modes/mode_params.h -----------------*- PUBLIC -*- H -*-===*/
/**
/// @file
/// @brief Primitive Parameters
///
/// This header contains parameter structures for all block modes.
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
    ///
    /// @remarks Set to 0 to  disable  padding, and 1 to  enable it - only the
    ///          least significant bit is used, all other bits are ignored.
    ///
    /// @remarks Padding is enabled by default if parameters are not used.
    **/
    size_t padding;
};

/** @brief CBC parameters.
**/
struct CBC_PARAMS
{
    /** Whether padding should be used.
    ///
    /// @remarks Set to 0 to  disable  padding, and 1 to  enable it - only the
    ///          least significant bit is used, all other bits are ignored.
    ///
    /// @remarks Padding is enabled by default if parameters are not used.
    **/
    size_t padding;
};

/*===----------------------------------------------------------------------===*/

#ifdef __cplusplus
}
#endif

#endif
