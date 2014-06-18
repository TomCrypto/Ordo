/*===-- common/query.h ---------------------------------*- PUBLIC -*- H -*-===*/
/**
*** @file
*** @brief Utility
***
*** This  header contains  declarations  for query  codes  used when  querying
*** information  from primitives  or  other library  objects.  The query  must
*** return a length or something relating to size, which is why it is used for
*** key lengths and related quantities.
***
*** The  query  codes  provide  a lightweight  mechanism  to  select  suitable
*** parameters when using the library,  and, alternatively, iterating over all
*** possible parameters  when necessary, while  still retaining some  level of
*** abstraction in user code.
***
*** All query functions take the following arguments:
*** - query code (one of the codes defined here)
*** - suggested value (type \c size_t)
***
*** They have  the following properties  (where \c  X stands for  the relevant
*** quantity of the concerned primitive, e.g. "valid key length for some block
*** cipher"):
***
*** - `query(code, 0)` returns the \b smallest \c X.
***
*** - `query(code, (size_t)-1)` returns the \b largest \c X.
***
*** - if `query(code, n) == n` then \c n is an \c X.
***
*** - if \c n is less than the largest \c X, then `query(code, n) > n`.
***
*** - if `query(code, n + 1) == n` then \c n is the \b largest \c X. Otherwise
***   `query(code, n + 1)` returns the next \c X (in increasing order).
***
*** The motivation for  designing this interface in this fashion  is to ensure
*** no information loss occurs when user input is provided to the library. For
*** instance, if the user  provides a 160-bit key to AES,  he will first query
*** the block cipher key length using \c #KEY_LEN_Q, suggesting a 160-bit key,
*** and the  AES cipher will  correctly identify the  ideal key length  as 192
*** bits, and not 128 bits (which would lead to part of the key being unused).
*** This allows software  using the library to dynamically  adjust to whatever
*** cryptographic primitives are in use without compromising security.
**/
/*===----------------------------------------------------------------------===*/

#ifndef ORDO_QUERY_H
#define ORDO_QUERY_H

/** @cond **/
#include "ordo/common/interface.h"
/** @endcond **/

#ifdef __cplusplus
extern "C" {
#endif

/*===----------------------------------------------------------------------===*/

/** @enum ORDO_QUERY
***
*** Query codes used by the library. These end in \c _Q.
***
*** @var ORDO_QUERY::KEY_LEN_Q
***
*** Query code to retrieve a key length.
***
*** Applicable to:
*** - block ciphers
*** - stream ciphers
***
*** @var ORDO_QUERY::BLOCK_SIZE_Q
***
*** Query code to retrieve a block size.
***
*** Applicable to:
*** - block ciphers
*** - hash functions
***
*** @remarks For hash functions, this is taken to be the input size of the
***          message block to  the compression function or, more formally,
***          the amount of data required to trigger a compression function
***          iteration. This may not be meaningful for all hash functions.
***
*** @var ORDO_QUERY::DIGEST_LEN_Q
***
*** Query code to retrieve the default digest length of a hash function.
***
*** @remarks The suggested value is ignored for this query code.
***
*** Applicable to:
*** - hash functions
***
*** @var ORDO_QUERY::IV_LEN_Q
***
*** Query code to retrieve an initialization vector length.
***
*** Applicable to:
*** - block modes
***
*** @remarks As the block  mode of operation  primitives use block ciphers
***          internally, the  returned  initialization vector length might
***          depend on the block cipher (likely its block size).
**/
enum ORDO_QUERY
{
    KEY_LEN_Q,
    BLOCK_SIZE_Q,
    DIGEST_LEN_Q,
    IV_LEN_Q
};

/*===----------------------------------------------------------------------===*/

#ifdef __cplusplus
}
#endif

#endif
