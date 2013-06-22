/**
 * @file aes.S
 *
 * \brief AES assembly code [ABI: Windows x64, Linux x64].
 *
 * This file contains an implementation of AES (Advanced Encryption Standard) for AES-NI-capable processors.
 * This technically works for 32-bit processors too, but the x86 version doesn't seem to recognize the forward
 * function declarations and complains about undefined references...
 *
 * \todo Fix 32-bit "undefined reference" bug.
 * \todo Implement AES key schedule with AES-NI, to get rid of the substitution box.
 *
 * @see aes.c
 * @see aes.h
 *
 */

#include <internal/asm/resolve.h>

/* Intel syntax only! */
.intel_syntax noprefix;

/* This is assembly for 64-bit Linux. */
#if defined (AES_X86_64_LINUX)

/* Declarations. */
.globl aes_forward_ASM
.globl aes_inverse_ASM

aes_forward_ASM:
    /* The key is passed in RSI, and the block in RDI. First, move the block in XMM0... */
    MOVDQA %XMM0, [%RDI]

    /* Move the initial key in XMM1... */
    MOVDQA %XMM1, [%RSI]
    ADD %RSI, 0x10

    /* Key whitening. */
    PXOR %XMM0, %XMM1

    /* Now, perform as many rounds as needed (the round number is passed in R8). */
    LOOPF:
        /* Move the appropriate key in XMM1. */
        MOVDQA %XMM1, [%RSI]
        ADD %RSI, 0x10

        /* Perform one AES round. */
        AESENC %XMM0, %XMM1

        /* Loop condition. */
        dec %RDX
        cmp %RDX, 1
        jne LOOPF

    /* Move the last key in XMM1. */
    MOVDQA %XMM1, [%RSI]

    /* Perform the last round and return. */
    AESENCLAST %XMM0, %XMM1
    MOVDQA [%RDI], %XMM0
    ret

aes_inverse_ASM:
    /* The last key is passed in RSI, and the block in RDI. First, move the block in XMM0... */
    MOVDQA %XMM0, [%RDI]

    /* Move the last key in XMM1... */
    MOVDQA %XMM1, [%RSI]
    SUB %RSI, 0x10

    /* Reverse the key whitening and return. */
    PXOR %XMM0, %XMM1

    /* Now, perform as many rounds as needed (the round number is passed in R8). */
    LOOPI:
        /* Move the appropriate key in XMM1. */
        MOVDQA %XMM1, [%RSI]
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
    MOVDQA %XMM1, [%RSI]

    /* Perform the last round decryption. */
    AESDECLAST %XMM0, %XMM1
    MOVDQA [%RDI], %XMM0
    ret

#elif defined (AES_X86_64_WINDOWS)

/* Declarations. */
.globl aes_forward_ASM
.globl aes_inverse_ASM

aes_forward_ASM:
    /* The key is passed in RDX, and the block in RCX. First, move the block in XMM0... */
    MOVDQA %XMM0, [%RCX]

    /* Move the initial key in XMM1... */
    MOVDQA %XMM1, [%RDX]
    ADD %RDX, 0x10

    /* Key whitening. */
    PXOR %XMM0, %XMM1

    /* Now, perform as many rounds as needed (the round number is passed in R8). */
    LOOPF:
        /* Move the appropriate key in XMM1. */
        MOVDQA %XMM1, [%RDX]
        ADD %RDX, 0x10

        /* Perform one AES round. */
        AESENC %XMM0, %XMM1

        /* Loop condition. */
        dec %R8
        cmp %R8, 1
        jne LOOPF

    /* Move the last key in XMM1. */
    MOVDQA %XMM1, [%RDX]

    /* Perform the last round and return. */
    AESENCLAST %XMM0, %XMM1
    MOVDQA [%RCX], %XMM0
    ret

aes_inverse_ASM:
    /* The last key is passed in RDX, and the block in RCX. First, move the block in XMM0... */
    MOVDQA %XMM0, [%RCX]

    /* Move the last key in XMM1... */
    MOVDQA %XMM1, [%RDX]
    SUB %RDX, 0x10

    /* Reverse the key whitening and return. */
    PXOR %XMM0, %XMM1

    /* Now, perform as many rounds as needed (the round number is passed in R8). */
    LOOPI:
        /* Move the appropriate key in XMM1. */
        MOVDQA %XMM1, [%RDX]
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
    MOVDQA %XMM1, [%RDX]

    /* Perform the last round decryption. */
    AESDECLAST %XMM0, %XMM1
    MOVDQA [%RCX], %XMM0
    ret

/* This is assembly for x86 (DEAD CODE). */
#elif (0)

/* Declarations. */
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
    MOVDQA %XMM0, [%EDX]

    /* Move the initial key in XMM1... */
    MOVDQA %XMM1, [%ECX]
    ADD %ECX, 0x10

    /* Key whitening. */
    PXOR %XMM0, %XMM1

    /* Now, perform as many rounds as needed (the round number is passed in R8). */
    LOOPF:
        /* Move the appropriate key in XMM1. */
        MOVDQA %XMM1, [%ECX]
        ADD %ECX, 0x10

        /* Perform one AES round. */
        AESENC %XMM0, %XMM1

        /* Loop condition. */
        dec %EAX
        cmp %EAX, 1
        jne LOOPF

    /* Move the last key in XMM1. */
    MOVDQA %XMM1, [%ECX]

    /* Perform the last round and return. */
    AESENCLAST %XMM0, %XMM1
    MOVDQA [%EDX], %XMM0
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
    MOVDQA %XMM0, [%EDX]

    /* Move the last key in XMM1... */
    MOVDQA %XMM1, [%ECX]
    SUB %ECX, 0x10

    /* Reverse the key whitening and return. */
    PXOR %XMM0, %XMM1

    /* Now, perform as many rounds as needed (the round number is passed in R8). */
    LOOPI:
        /* Move the appropriate key in XMM1. */
        MOVDQA %XMM1, [%ECX]
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
    MOVDQA %XMM1, [%ECX]

    /* Perform the last round decryption. */
    AESDECLAST %XMM0, %XMM1
    MOVDQA [%EDX], %XMM0
    ret

#endif
