#ifndef ORDO_ECB_MODE_H
#define ORDO_ECB_MODE_H

#include <enc/block_modes.h>

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * @file ecb.h
 * @brief ECB block mode of operation.
 *
 * The ECB mode divides the input message into blocks of the cipher's block
 * size, and encrypts them individually and independently. If the input
 * message's length is not a multiple of the cipher's block size, a padding
 * mechanism is enabled by default which will pad the message to the correct
 * length (and remove the extra data upon decryption). Padding may be disabled
 * via \c ECB_PARAMS, putting constraints on the input message.
 *
 * The ECB mode does not require an initialization vector.
 *
 * Note that the ECB mode is insecure in almost all situations and is not
 * recommended for general purpose use.
*/

struct ECB_STATE;

/*! Allocates an ECB state.
 @remarks Refer to \c block_mode_alloc() for an overview of the function.
 @remarks A valid cipher state need not be provided here yet, but a valid
          cipher object must be as the ECB mode state dynamically allocates
          some memory according to the block cipher's block size.
*/
struct ECB_STATE *ecb_alloc(const struct BLOCK_CIPHER* cipher,
                            void *cipher_state);

/*! Initializes an ECB state.
 @remarks Refer to \c block_mode_init() for an overview of this function.
 @remarks The \c iv_len parameter must be zero.
 @retval #ORDO_SUCCESS if the function encountered no error.
 @retval #ORDO_ARG if the \c iv_len parameter was not zero.
*/
int ecb_init(struct ECB_STATE *state,
             const struct BLOCK_CIPHER *cipher,
             void *cipher_state,
             const void *iv,
             size_t iv_len,
             int direction,
             const struct ECB_PARAMS *params);

/*! Encrypts or decrypts a buffer.
 @remarks Refer to \c block_mode_update() for an overview of this function.
 @remarks \c in and \c out may point to the same buffer, in order to achieve
          in-place encryption/decryption.
*/
void ecb_update(struct ECB_STATE *state,
                const struct BLOCK_CIPHER *cipher,
                void *cipher_state,
                const unsigned char *in,
                size_t in_len,
                unsigned char *out,
                size_t *out_len);

/*! Finalizes an ECB state.
 @remarks Refer to \c block_mode_final() for an overview of this function.
 @retval #ORDO_SUCCESS if the function encountered no error.
 @retval #ORDO_LEFTOVER if padding is disabled and the total length in bytes of
                        the data to encrypt was not a multiple of the block
                        cipher's block size.
 @retval #ORDO_LEFTOVER if, when decrypting, the total length in bytes of the
                        data to decrypt was not a multiple of the block
                        cipher's block size.
 @retval #ORDO_PADDING if, when decrypting, the last ciphertext block does not
                       describe a valid PKCS padding block (in which case
                       decryption cannot be unambiguously carried out).
 @remarks If the function returns #ORDO_LEFTOVER, the number of leftover bytes
          will be written to \c *out_len.
 @remarks If the function returns #ORDO_PADDING, \c *out_len will be zeroed.
 @remarks \c out_len may not be nil.
*/
int ecb_final(struct ECB_STATE *state,
              const struct BLOCK_CIPHER *cipher,
              void *cipher_state,
              unsigned char *out,
              size_t *out_len);

/*! Frees an ECB state.
 @remarks Refer to \c block_mode_free() for an overview of this function.
*/
void ecb_free(struct ECB_STATE *state,
              const struct BLOCK_CIPHER *cipher,
              void *cipher_state);

/*! Performs a deep-copy of an ECB state into another.
 @remarks Refer to \c block_mode_copy() for an overview of this function.
 @remarks The source and destination ECB states must have been allocated using
          the same block cipher, and, if initialized, with the same parameters.
*/
void ecb_copy(struct ECB_STATE *dst,
              const struct ECB_STATE *src,
              const struct BLOCK_CIPHER *cipher);

void ecb_set_mode(struct BLOCK_MODE *mode);

#ifdef __cplusplus
}
#endif

#endif
