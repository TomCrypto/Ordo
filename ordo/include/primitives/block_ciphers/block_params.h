#ifndef ORDO_BLOCK_PARAMS_H
#define ORDO_BLOCK_PARAMS_H

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/*! Threefish-256 cipher parameters. */
struct THREEFISH256_PARAMS
{
    /*! The tweak word, on a pair of 64-bit words. */
    uint64_t tweak[2];
};

/*! AES cipher parameters. */
struct AES_PARAMS
{
    /*! The number of rounds to use.
     @remarks The defaults are 10 for a 128-bit key, 12 for a 192-bit key and
              14 for a 256-bit key, and are standardized. It is strongly
              discouraged to lower the number of rounds below the defaults.
    */
    size_t rounds;
};

#ifdef __cplusplus
}
#endif

#endif
