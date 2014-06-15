/*===-- misc/os_random.h -------------------------------*- PUBLIC -*- H -*-===*/
/**
*** @file
*** @brief Module
***
*** Exposes  the  OS  CSPRNG  (Cryptographically  Secure  PseudoRandom  Number
*** Generator) interface, which  is basically a cross-platform  wrapper to the
*** OS-provided entropy pool. To learn more about how it is implemented, go to
*** the source code or find out what facilities your operating system provides
*** for entropy gathering.
**/
/*===----------------------------------------------------------------------===*/

#ifndef ORDO_OS_RANDOM_H
#define ORDO_OS_RANDOM_H

/** @cond **/
#include "ordo/common/interface.h"
/** @endcond **/

#ifdef __cplusplus
extern "C" {
#endif

/*===----------------------------------------------------------------------===*/

/** Generates cryptographically secure pseudorandom numbers.
***
*** @param [out]    out            The destination buffer.
*** @param [in]     len            The number of bytes to generate.
***
*** @returns \c #ORDO_SUCCESS on success, else an error code.
***
*** @remarks This function uses the CSPRNG provided by your operating system.
***
*** @remarks If the platform does not provide this feature, this function will
***          always fail with the \c #ORDO_FAIL error message, and any data in
***          the buffer should be discarded as indeterminate.
**/
ORDO_PUBLIC
int os_random(void *out, size_t len);

/** Generates cryptographically secure pseudorandom numbers, the function will
*** make a best effort attempt to access the operating system entropy pool and
*** so, ideally, should return exactly \c len bytes of entropy, whereas the \c
*** os_random function need only return *enough* entropy for the output stream
*** to be computationally indistinguishable from a non-random stream. However,
*** keep in mind that this function is **not required** to behave as such.
***
*** @param [out]    out            The destination buffer.
*** @param [in]     len            The number of bytes to generate.
***
*** @returns \c #ORDO_SUCCESS on success, else an error code.
***
*** @remarks If your platform doesn't provide this feature, this function will
***          fall back to \c os_random() (there is no way to know whether this
***          feature is available, this is by design).
***
*** @remarks You should not need to know whether this feature is available, as
***          this function will make a "best effort" attempt to obtain entropy
***          from the operating system - you should use this function for high
***          security uses such as generating private keys (it has a high cost
***          so don't use it for e.g. nonces and initialization vectors).
**/
ORDO_PUBLIC
int os_secure_random(void *out, size_t len);

/*===----------------------------------------------------------------------===*/

#ifdef __cplusplus
}
#endif

#endif
