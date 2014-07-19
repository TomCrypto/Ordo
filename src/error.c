/*===-- error.c ---------------------------------------*- generic -*- C -*-===*/

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

#include "ordo/common/error.h"

/*===----------------------------------------------------------------------===*/

const char *ordo_error_msg(int code)
{
    switch (code)
    {
        case ORDO_SUCCESS:  return "No error occurred";
        case ORDO_ARG:      return "Invalid argument provided";
        case ORDO_FAIL:     return "An external error occurred";
        case ORDO_KEY_LEN:  return "The key length is invalid";
        case ORDO_PADDING:  return "The padding block cannot be recognized";
        case ORDO_LEFTOVER: return "There is leftover input data";
        default:            return "Unknown error code";
    }
}
