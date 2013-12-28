BITS 64

global aes_forward_ASM
global aes_inverse_ASM

section .text

aes_forward_ASM:
    MOVDQU XMM0, [RCX]

    MOVDQU XMM1, [RDX]
    ADD RDX, 0x10

    PXOR XMM0, XMM1

    .loopf:
        MOVDQU XMM1, [RDX]
        ADD RDX, 0x10

        AESENC XMM0, XMM1

        dec R8
        cmp R8, 1
        jne .loopf

    MOVDQU XMM1, [RDX]

    AESENCLAST XMM0, XMM1
    MOVDQU [RCX], XMM0
    ret

aes_inverse_ASM:
    MOVDQU XMM0, [RCX]

    MOV R10, R8
    SHL R10, 4
    ADD RDX, R10

    MOVDQU XMM1, [RDX]
    SUB RDX, 0x10

    PXOR XMM0, XMM1

    .loopi:
        MOVDQU XMM1, [RDX]
        SUB RDX, 0x10

        AESIMC XMM1, XMM1

        AESDEC XMM0, XMM1

        dec R8
        cmp R8, 1
        jne .loopi

    MOVDQU XMM1, [RDX]

    AESDECLAST XMM0, XMM1
    MOVDQU [RCX], XMM0
    ret
