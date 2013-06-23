#ifndef ORDO_STREAM_PARAMS_H
#define ORDO_STREAM_PARAMS_H

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file stream_params.h
 * @brief Stream cipher parameters.
 *
 * This header contains parameter structures for all stream cipher primitives.
*/

/*! @brief RC4 stream cipher parameters. */
struct RC4_PARAMS
{
    /*! The number of keystream bytes to drop prior to encryption.
     @remarks Setting this implements the RC4-drop variant.
     @remarks If the \c RC4_PARAMS structure is not passed to the RC4 stream
              cipher primitive, the default drop is 2048. */
    size_t drop;
};

#ifdef __cplusplus
}
#endif

#endif
