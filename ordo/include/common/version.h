#ifndef VERSION_H
#define VERSION_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file version.h
 * \brief Library version header.
 *
 * This header allows code to access the library version, build details and other information.
 *
 * @see version.c
 *
 */

#include <common/ordotypes.h>

/*! \brief Library build information.

 * Regarding the feature flag fields, 0 means the feature
 * is not targeted, any other value means that it is. */
typedef struct ORDO_BUILD_INFO
{
    /*! The library's version. */
    char* version;
    /*! The library's devtag. */
    char* devtag;
    /*! The build type. */
    char* build;
    /*! The library's platform. */
    char* platform;
    /*! The targeted ABI. */
    char* ABI;
    /*! The native word size, in bits. */
    int wordSize;
    /*! Whether AES-NI is targeted. */
    int feature_AES;
} ORDO_BUILD_INFO;

/*! Returns library build information in a structure. */
const ORDO_BUILD_INFO* ordoBuildInfo();

#ifdef __cplusplus
}
#endif

#endif
