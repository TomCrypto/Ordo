#include "ordo/common/errors.h"

/******************************************************************************/

const char* error_msg(int code)
{
    switch (code)
    {
        case ORDO_SUCCESS:  return "No error occurred";
        case ORDO_ARG:      return "Invalid argument provided";
        case ORDO_FAIL:     return "An external error occurred";
        case ORDO_KEY_LEN:  return "The key length is invalid";
        case ORDO_PADDING:  return "The padding block cannot be recognized";
        case ORDO_LEFTOVER: return "There is leftover input data";
        case ORDO_ALLOC:    return "Memory allocation failed";
        default:            return "Unknown error code";
    }
}
