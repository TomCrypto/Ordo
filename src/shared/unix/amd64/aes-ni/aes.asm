;/===-- aes.asm --------------------*- shared/unix/amd64/aes-ni -*- ASM -*-===//

; AES-NI implementation

;/===----------------------------------------------------------------------===//

BITS 64

global aes_forward_ASM
global aes_inverse_ASM

section .text

aes_forward_ASM:
    MOVDQU XMM0, [RDI]

    MOVDQU XMM1, [RSI]
    ADD RSI, 0x10

    PXOR XMM0, XMM1

    .loopf:
        MOVDQU XMM1, [RSI]
        ADD RSI, 0x10

        AESENC XMM0, XMM1

        dec RDX
        cmp RDX, 1
        jne .loopf

    MOVDQU XMM1, [RSI]

    AESENCLAST XMM0, XMM1
    MOVDQU [RDI], XMM0
    ret

aes_inverse_ASM:
    MOVDQU XMM0, [RDI]

    MOV RAX, RDX
    SHL RAX, 4
    ADD RSI, RAX

    MOVDQU XMM1, [RSI]
    SUB RSI, 0x10

    PXOR XMM0, XMM1

    .loopi:
        MOVDQU XMM1, [RSI]
        SUB RSI, 0x10

        AESIMC XMM1, XMM1

        AESDEC XMM0, XMM1

        dec RDX
        cmp RDX, 1
        jne .loopi

    MOVDQU XMM1, [RSI]

    AESDECLAST XMM0, XMM1
    MOVDQU [RDI], XMM0
    ret
