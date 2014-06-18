/*===-- common/errors.h --------------------------------*- PUBLIC -*- H -*-===*/
/**
*** @file
*** @brief Utility
***
*** This header  exposes error codes emitted  by the library. Code  which uses
*** the  library should  always  use the  explicit error  codes  to check  for
*** errors, with the sole exception of \c #ORDO_SUCCESS which is guaranteed to
*** be zero.
**/
/*===----------------------------------------------------------------------===*/

#ifndef ORDO_ERROR_H
#define ORDO_ERROR_H

/** @cond **/
#include "ordo/common/interface.h"
/** @endcond **/

#ifdef __cplusplus
extern "C" {
#endif

/*===----------------------------------------------------------------------===*/

/** Generates a readable error message from an error code.
***
*** @param [in]     code           The error code to interpret.
***
*** @returns A null-terminated string containing the error description.
***
*** @remarks This function is intended for debugging purposes.
**/
ORDO_PUBLIC
const char *ordo_error_msg(int code);

/** @enum ORDO_ERROR
***
*** Error codes used by the library.
***
*** @var ORDO_ERROR::ORDO_SUCCESS
***
*** The function succeeded
***
*** @remarks This is always  defined as zero and is returned if a function
***          encountered no error, unless specified otherwise.
***
*** @var ORDO_ERROR::ORDO_FAIL
***
*** The function failed due to an external error.
***
*** @remarks This often indicates  failure of an  external component, such
***          as the pseudorandom number generator  provided by the OS (see
***          #os_random). The library is not responsible for this error.
***
*** @var ORDO_ERROR::ORDO_LEFTOVER
***
*** User input was left over unprocessed.
***
*** @remarks This applies  to block  cipher modes  of operation  for which
***          padding has been  disabled. If the input  plaintext length is
***          not a multiple of the cipher's block size, then the remaining
***          incomplete block cannot be  handled without padding, which is
***          an error  as it generally  leads to inconsistent  behavior on
***          the part of the user.
***
*** @var ORDO_ERROR::ORDO_KEY_LEN
***
*** The key length provided is invalid.
***
*** @remarks This occurs if  you provide a key of an  invalid length, such
***          as  passing a  128-bit  key  into a  cipher  which expects  a
***          192-bit key. Primitives  either have a range  of possible key
***          lengths  (often characterized  by a  minimum and  maximum key
***          length,  but  this  varies  among  algorithms)  or  only  one
***          specific key length.  If you need to  accept arbitrary length
***          keys, you  should consider hashing  your key in  some fashion
***          before using it for encryption, for instance using a KDF.
***
*** @remarks The \c  block_query() function  can be used  to select a good
***          key  length  for a given  block cipher via the  \c #KEY_LEN_Q
***          query code. For stream ciphers, use \c stream_query().
***
*** @var ORDO_ERROR::ORDO_PADDING
***
*** The padding was not recognized and decryption could not be completed.
***
*** @remarks This  applies to  block  cipher modes  for  which padding  is
***          enabled. If the last  block containing padding information is
***          malformed,  the  padding  will generally  be  unreadable  and
***          the  correct  message  length  cannot  be  retrieved,  making
***          correct decryption impossible. Note this is not guaranteed to
***          occur  if the  padding block  is corrupted.  In other  words,
***          if  \c  #ORDO_PADDING  is  returned,  the  padding  block  is
***          certainly  corrupted, however  it may  still be  even if  the
***          library returns success (the  returned plaintext will then be
***          incorrect). If you \b must  ensure the plaintext is decrypted
***          correctly - and you probably should  - you will want to use a
***          MAC (Message  Authentication Code) along with  encryption, or
***          an authenticated block cipher mode of operation.
***
*** @var ORDO_ERROR::ORDO_ARG
***
*** An invalid argument was passed to a function.
***
*** @remarks This is  a generic error  which is returned when  the library
***          finds an invalid parameter  which would lead to inconsistent,
***          undefined, or  profoundly insecure  behavior. Make  sure your
***          arguments are correct and do not contradict one another.
***
*** @remarks Keep in mind  that the library cannot possibly catch all such
***          errors, and you  should still read the  documentation  if you
***          are not sure what you are doing is valid.
**/
enum ORDO_ERROR
{
    ORDO_SUCCESS,
    ORDO_FAIL,
    ORDO_LEFTOVER,
    ORDO_KEY_LEN,
    ORDO_PADDING,
    ORDO_ARG
};

/*===----------------------------------------------------------------------===*/

#ifdef __cplusplus
}
#endif

#endif
