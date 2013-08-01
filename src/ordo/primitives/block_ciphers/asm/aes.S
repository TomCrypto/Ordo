#include "ordo/internal/asm/resolve.h"

#if defined (AES_X86_64_LINUX)

.intel_syntax noprefix;

.globl aes_forward_ASM
.globl aes_inverse_ASM

aes_forward_ASM:
    /* The key is passed in RSI, and the block in RDI. First, move the block in XMM0... */
    MOVDQU %XMM0, [%RDI]

    /* Move the initial key in XMM1... */
    MOVDQU %XMM1, [%RSI]
    ADD %RSI, 0x10

    /* Key whitening. */
    PXOR %XMM0, %XMM1

    /* Now, perform as many rounds as needed (the round number is passed in R8). */
    LOOPF:
        /* Move the appropriate key in XMM1. */
        MOVDQU %XMM1, [%RSI]
        ADD %RSI, 0x10

        /* Perform one AES round. */
        AESENC %XMM0, %XMM1

        /* Loop condition. */
        dec %RDX
        cmp %RDX, 1
        jne LOOPF

    /* Move the last key in XMM1. */
    MOVDQU %XMM1, [%RSI]

    /* Perform the last round and return. */
    AESENCLAST %XMM0, %XMM1
    MOVDQU [%RDI], %XMM0
    ret

aes_inverse_ASM:
    /* The last key is passed in RSI, and the block in RDI. First, move the block in XMM0... */
    MOVDQU %XMM0, [%RDI]

    /* Move the last key in XMM1... */
    MOVDQU %XMM1, [%RSI]
    SUB %RSI, 0x10

    /* Reverse the key whitening and return. */
    PXOR %XMM0, %XMM1

    /* Now, perform as many rounds as needed (the round number is passed in R8). */
    LOOPI:
        /* Move the appropriate key in XMM1. */
        MOVDQU %XMM1, [%RSI]
        SUB %RSI, 0x10

        /* Feed the key into the IMC. */
        AESIMC %XMM1, %XMM1

        /* Perform one AES round. */
        AESDEC %XMM0, %XMM1

        /* Loop condition. */
        dec %RDX
        cmp %RDX, 1
        jne LOOPI

    /* Move the first key in XMM1. */
    MOVDQU %XMM1, [%RSI]

    /* Perform the last round decryption. */
    AESDECLAST %XMM0, %XMM1
    MOVDQU [%RDI], %XMM0
    ret

#elif defined (AES_X86_64_WINDOWS)

.intel_syntax noprefix;

.globl aes_forward_ASM
.globl aes_inverse_ASM

aes_forward_ASM:
    /* The key is passed in RDX, and the block in RCX. First, move the block in XMM0... */
    MOVDQU %XMM0, [%RCX]

    /* Move the initial key in XMM1... */
    MOVDQU %XMM1, [%RDX]
    ADD %RDX, 0x10

    /* Key whitening. */
    PXOR %XMM0, %XMM1

    /* Now, perform as many rounds as needed (the round number is passed in R8). */
    LOOPF:
        /* Move the appropriate key in XMM1. */
        MOVDQU %XMM1, [%RDX]
        ADD %RDX, 0x10

        /* Perform one AES round. */
        AESENC %XMM0, %XMM1

        /* Loop condition. */
        dec %R8
        cmp %R8, 1
        jne LOOPF

    /* Move the last key in XMM1. */
    MOVDQU %XMM1, [%RDX]

    /* Perform the last round and return. */
    AESENCLAST %XMM0, %XMM1
    MOVDQU [%RCX], %XMM0
    ret

aes_inverse_ASM:
    /* The last key is passed in RDX, and the block in RCX. First, move the block in XMM0... */
    MOVDQU %XMM0, [%RCX]

    /* Move the last key in XMM1... */
    MOVDQU %XMM1, [%RDX]
    SUB %RDX, 0x10

    /* Reverse the key whitening and return. */
    PXOR %XMM0, %XMM1

    /* Now, perform as many rounds as needed (the round number is passed in R8). */
    LOOPI:
        /* Move the appropriate key in XMM1. */
        MOVDQU %XMM1, [%RDX]
        SUB %RDX, 0x10

        /* Feed the key into the IMC. */
        AESIMC %XMM1, %XMM1

        /* Perform one AES round. */
        AESDEC %XMM0, %XMM1

        /* Loop condition. */
        dec %R8
        cmp %R8, 1
        jne LOOPI

    /* Move the first key in XMM1. */
    MOVDQU %XMM1, [%RDX]

    /* Perform the last round decryption. */
    AESDECLAST %XMM0, %XMM1
    MOVDQU [%RCX], %XMM0
    ret

#elif (0)

.globl aes_forward_ASM
.globl aes_inverse_ASM

/***********************
 * CURRENTLY DEAD CODE *
 ***********************/

aes_forward_ASM:
    /* Stack:
     * -- top -- *
     *   round   *
     *    key    *
     *   block   *
     * ......... */
    POP %EAX /* -> round */
    POP %ECX /* -> key   */
    POP %EDX /* -> block */

    /* Move the block in XMM0... */
    MOVDQU %XMM0, [%EDX]

    /* Move the initial key in XMM1... */
    MOVDQU %XMM1, [%ECX]
    ADD %ECX, 0x10

    /* Key whitening. */
    PXOR %XMM0, %XMM1

    /* Now, perform as many rounds as needed (the round number is passed in R8). */
    LOOPF:
        /* Move the appropriate key in XMM1. */
        MOVDQU %XMM1, [%ECX]
        ADD %ECX, 0x10

        /* Perform one AES round. */
        AESENC %XMM0, %XMM1

        /* Loop condition. */
        dec %EAX
        cmp %EAX, 1
        jne LOOPF

    /* Move the last key in XMM1. */
    MOVDQU %XMM1, [%ECX]

    /* Perform the last round and return. */
    AESENCLAST %XMM0, %XMM1
    MOVDQU [%EDX], %XMM0
    ret

aes_inverse_ASM:
    /* Stack:
     * -- top -- *
     *   round   *
     *    key    *
     *   block   *
     * ......... */
    POP %EAX /* -> round */
    POP %ECX /* -> key   */
    POP %EDX /* -> block */

    /* Move the block in XMM0... */
    MOVDQU %XMM0, [%EDX]

    /* Move the last key in XMM1... */
    MOVDQU %XMM1, [%ECX]
    SUB %ECX, 0x10

    /* Reverse the key whitening and return. */
    PXOR %XMM0, %XMM1

    /* Now, perform as many rounds as needed (the round number is passed in R8). */
    LOOPI:
        /* Move the appropriate key in XMM1. */
        MOVDQU %XMM1, [%ECX]
        SUB %ECX, 0x10

        /* Feed the key into the IMC. */
        AESIMC %XMM1, %XMM1

        /* Perform one AES round. */
        AESDEC %XMM0, %XMM1

        /* Loop condition. */
        dec %EAX
        cmp %EAX, 1
        jne LOOPI

    /* Move the first key in XMM1. */
    MOVDQU %XMM1, [%ECX]

    /* Perform the last round decryption. */
    AESDECLAST %XMM0, %XMM1
    MOVDQU [%EDX], %XMM0
    ret

#endif
