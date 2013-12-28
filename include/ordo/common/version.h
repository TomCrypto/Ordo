//===-- common/version.h -------------------------------*- PUBLIC -*- H -*-===//
///
/// @file
/// @brief Utility
///
/// This header exposes functionality relating  to the Ordo library's version,
/// architecture it was built for, and any additional features (such as AES-NI
/// hardware instructions).
///
/// It is  probably not  useful to  reason about  the information  this header
/// exposes, but it can be displayed in a human-readable format as needed.
///
//===----------------------------------------------------------------------===//

#ifndef ORDO_VERSION_H
#define ORDO_VERSION_H

/// @cond
#include "ordo/common/interface.h"
/// @endcond

#ifdef __cplusplus
extern "C" {
#endif

//===----------------------------------------------------------------------===//

/// Returns the build  tag for the library, which includes  its name, version,
/// host system, architecture, and any additional information.
///
/// @returns The build tag, in a human-readable format.
ORDO_PUBLIC
const char *ordo_build_tag(void);

//===----------------------------------------------------------------------===//

#ifdef __cplusplus
}
#endif

#endif
