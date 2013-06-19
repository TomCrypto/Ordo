#ifndef ORDO_HASH_PARAMS_H
#define ORDO_HASH_PARAMS_H

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/*! \brief Skein-256 hash parameters.
 *
 * A parameter structure for Skein-256. */
struct SKEIN256_PARAMS
{
    /*! The schema identifier, on four bytes. */
    uint8_t schema[4];
    /*! The version number, on two bytes. */
    uint8_t version[2];
    /*! Reserved - must be left zero. */
    uint8_t reserved[2];
    /*! Desired output length, in bits (note the actual output digest will be truncated to a byte boundary, so this should really always be a multiple of 8). */
    uint64_t outputLength;
    /*! Unused, must be left zero. */
    uint8_t unused[16];
};

#ifdef __cplusplus
}
#endif

#endif
