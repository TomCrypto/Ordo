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
 * This header allows code to access the library version.
*/

/*! The major version number of the library. */
int ordo_version_major();
/*! The minor version number of the library. */
int ordo_version_minor();
/*! The revision number of the library. */
int ordo_version_rev();

#ifdef __cplusplus
}
#endif

#endif
