#ifndef ORDO_HASH_PARAMS_H
#define ORDO_HASH_PARAMS_H

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file hash_params.h
 * @brief Hash function parameters.
 *
 * This header contains parameter structures for all hash function primitives.
*/

/*! @brief Skein-256 hash function parameters. 
    @remarks Refer to the Skein specification to know more about what each
             parameter field stands for. */
struct SKEIN256_PARAMS
{
    /*! The schema identifier, on four bytes. */
    uint8_t schema[4];
    /*! The version number, on two bytes. */
    uint8_t version[2];
    /*! Reserved, should be left zero according to the Skein specification. */
    uint8_t reserved[2];
    /*! Desired output length, in bits.
     @remarks This parameter affects the hash function's digest length.
     @remarks The actual output length will be in bytes, and this parameter
              will be truncated to a byte boundary, so this should be a
              multiple of 8.
    */
    uint64_t outputLength;
    /*! Unused, should be left zero according to the Skein specification. */
    uint8_t unused[16];
};

#ifdef __cplusplus
}
#endif

#endif
