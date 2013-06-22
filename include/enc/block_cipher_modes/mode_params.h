#ifndef ORDO_MODE_PARAMS_H
#define ORDO_MODE_PARAMS_H

#include <stdlib.h>

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/*! \brief ECB mode of operation parameters.
 *
 * A parameter structure for ECB mode - this only contains whether padding should be enabled. */
struct ECB_PARAMS
{
    /*! Set the least significant bit to 0 to disable padding, 1 to enable it. All other bits are ignored. The default
    * behaviour is 1. */
    size_t padding;
};

/*! \brief CBC mode of operation parameters.
 *
 * A parameter structure for CBC mode - this only contains whether padding should be enabled. */
struct CBC_PARAMS
{
    /*! Set the least significant bit to 0 to disable padding, 1 to enable it. All other bits are ignored. The default
    * behaviour is 1. */
    size_t padding;
};

#ifdef __cplusplus
}
#endif

#endif
