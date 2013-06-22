#ifndef ORDO_STREAM_PARAMS_H
#define ORDO_STREAM_PARAMS_H

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/*! RC4 stream cipher parameters. */
struct RC4_PARAMS
{
    /*! The number of keystream bytes to drop prior to encryption. */
    size_t drop;
};

#ifdef __cplusplus
}
#endif

#endif
