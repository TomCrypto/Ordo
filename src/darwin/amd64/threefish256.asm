;/===-- threefish256.asm ------------------*- shared/unix/amd64 -*- ASM -*-===*/

; Threefish-256 implementation for AMD64

;/===----------------------------------------------------------------------===*/

BITS 64

global _threefish256_forward_ASM
global _threefish256_inverse_ASM

section .text

_threefish256_forward_ASM:
    xor RAX, RAX

    mov  R8, [RDI + 0x00]
    mov  R9, [RDI + 0x08]
    mov R10, [RDI + 0x10]
    mov R11, [RDI + 0x18]

    add  R8, [RSI + 0x00]
    add  R9, [RSI + 0x08]
    add R10, [RSI + 0x10]
    add R11, [RSI + 0x18]

    .loopf:
        add  R8,  R9
        rol  R9,   14
        xor  R9,  R8
        add R10, R11
        rol R11,   16
        xor R11, R10

        add  R8, R11
        rol R11,   52
        xor R11,  R8
        add R10,  R9
        rol  R9,   57
        xor  R9, R10

        add  R8,  R9
        rol  R9,   23
        xor  R9,  R8
        add R10, R11
        rol R11,   40
        xor R11, R10

        add  R8, R11
        rol R11,    5
        xor R11,  R8
        add R10,  R9
        rol  R9,   37
        xor  R9, R10

        add  R8, [RSI + 0x20 + 0x00]
        add  R9, [RSI + 0x20 + 0x08]
        add R10, [RSI + 0x20 + 0x10]
        add R11, [RSI + 0x20 + 0x18]

        add  R8,  R9
        rol  R9,   25
        xor  R9,  R8
        add R10, R11
        rol R11,   33
        xor R11, R10

        add  R8, R11
        rol R11,   46
        xor R11,  R8
        add R10,  R9
        rol  R9,   12
        xor  R9, R10

        add  R8,  R9
        rol  R9,   58
        xor  R9,  R8
        add R10, R11
        rol R11,   22
        xor R11, R10

        add  R8, R11
        rol R11,   32
        xor R11,  R8
        add R10,  R9
        rol  R9,   32
        xor  R9, R10

        add  R8, [RSI + 0x40 + 0x00]
        add  R9, [RSI + 0x40 + 0x08]
        add R10, [RSI + 0x40 + 0x10]
        add R11, [RSI + 0x40 + 0x18]

        add RSI, 0x40

        inc RAX
        cmp RAX, 9
        jne .loopf

    mov [RDI + 0x00],  R8
    mov [RDI + 0x08],  R9
    mov [RDI + 0x10], R10
    mov [RDI + 0x18], R11

    ret

_threefish256_inverse_ASM:
    xor RAX, RAX

    add RSI, 0x240

    mov  R8, [RDI + 0x00]
    mov  R9, [RDI + 0x08]
    mov R10, [RDI + 0x10]
    mov R11, [RDI + 0x18]

    .loopi:
        sub  R8, [RSI + 0x00]
        sub  R9, [RSI + 0x08]
        sub R10, [RSI + 0x10]
        sub R11, [RSI + 0x18]

        xor R11,  R8
        ror R11,   32
        sub  R8, R11
        xor  R9, R10
        ror  R9,   32
        sub R10,  R9

        xor  R9,  R8
        ror  R9,   58
        sub  R8,  R9
        xor R11, R10
        ror R11,   22
        sub R10, R11

        xor R11,  R8
        ror R11,   46
        sub  R8, R11
        xor  R9, R10
        ror  R9,   12
        sub R10,  R9

        xor  R9,  R8
        ror  R9,   25
        sub  R8,  R9
        xor R11, R10
        ror R11,   33
        sub R10, R11

        sub  R8, [RSI - 0x20 + 0x00]
        sub  R9, [RSI - 0x20 + 0x08]
        sub R10, [RSI - 0x20 + 0x10]
        sub R11, [RSI - 0x20 + 0x18]

        xor R11,  R8
        ror R11,    5
        sub  R8, R11
        xor  R9, R10
        ror  R9,   37
        sub R10,  R9

        xor  R9,  R8
        ror  R9,   23
        sub  R8,  R9
        xor R11, R10
        ror R11,   40
        sub R10, R11

        xor R11,  R8
        ror R11,   52
        sub  R8, R11
        xor  R9, R10
        ror  R9,   57
        sub R10,  R9

        xor  R9,  R8
        ror  R9,   14
        sub  R8,  R9
        xor R11, R10
        ror R11,   16
        sub R10, R11

        sub RSI, 0x40

        inc RAX
        cmp RAX, 9
        jne .loopi

    sub  R8, [RSI + 0x00]
    sub  R9, [RSI + 0x08]
    sub R10, [RSI + 0x10]
    sub R11, [RSI + 0x18]

    mov [RDI + 0x00],  R8
    mov [RDI + 0x08],  R9
    mov [RDI + 0x10], R10
    mov [RDI + 0x18], R11

    ret
