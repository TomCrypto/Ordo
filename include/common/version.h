#ifndef ORDO_VERSION_H
#define ORDO_VERSION_H

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * @file version.h
 * @brief Library version header.
 *
 * This header allows code to access the library version. It also contains
 * some information about the library such as the platform it was compiled
 * for, any additional build flags used, and so on.
*/

/*! The major version number of the library. */
int ordo_version_major(void);
/*! The minor version number of the library. */
int ordo_version_minor(void);
/*! The revision number of the library. */
int ordo_version_rev(void);

/*! The name of the platform the library was built for. */
const char* ordo_platform(void);

/*! The word size of the architecture the library was built for. */
int ordo_word_size(void);

#ifdef __cplusplus
}
#endif

#endif
