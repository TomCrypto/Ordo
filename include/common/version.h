#ifndef ORDO_VERSION_H
#define ORDO_VERSION_H

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file version.h
 * \brief Library version header.
 *
 * This header allows code to access the library version.
*/

/*! Returns the major version number of the library. */
int ordo_version_major();
/*! Returns the minor version number of the library. */
int ordo_version_minor();
/*! Returns the revision number of the library. */
int ordo_version_rev();

#ifdef __cplusplus
}
#endif

#endif
