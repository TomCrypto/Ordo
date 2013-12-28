;/===-- rc4.asm ---------------------------------*- win32/amd64 -*- ASM -*-===//

; RC4 implementation optimized for AMD64.
;
; Author: Marc Bevand <bevand_m (at) epita.fr>
; Licence: I hereby disclaim the copyright on this code and place it
; in the public domain.
;
; The code has been designed to be easily integrated into openssl:
; the exported RC4() function can replace the actual implementations
; openssl already contains. Please note that when linking with openssl,
; it requires that sizeof(RC4_INT) == 8. So openssl must be compiled
; with -DRC4_INT='unsigned long'.
;
; The throughput achieved by this code is about 320 MBytes/sec, on
; a 1.8 GHz AMD Opteron (rev C0) processor.
;
; NOTE: Reassembled for NASM (original is AT&T/gas)

;/===----------------------------------------------------------------------===//

BITS 64

global rc4_update_ASM

section .text

rc4_update_ASM:
    push   rbp
    push   rbx

    ; Translate Linux->Windows x86_64 calling convention
    push rsi
    push rdi

    mov rax,       rcx
    mov rcx,       rdi
    mov rdi,       rax

    mov rax,       rdx
    mov rdx,       rsi
    mov rsi,       rax

    mov rax,       r8
    mov r8,        rdx
    mov rdx,       rax

    mov rax,       r9
    mov r9,        rcx
    mov rcx,       rax
    ; end translation

    mov    rbp,rdi
    mov    rbx,rsi
    mov    rsi,rdx
    mov    rdi,rcx
    mov    rcx, [rbp+0x0]
    mov    rdx, [rbp+0x8]
    add    rbp,0x10
    inc    rcx
    and    rcx,0xff
    lea    rbx,[rbx+rsi*1-0x8]
    mov    r9,rbx
    mov    rax, [rbp+rcx*8+0x0]
    cmp    rbx,rsi
    jl     .Lend

.Lstart:
    add    rsi,0x8
    add    rdi,0x8
    mov    r11,0x8

.loop1:
    add    dl,al
    mov    ebx, [rbp+rdx*8+0x0]
    mov    [rbp+rcx*8+0x0],ebx
    add    bl,al
    mov    [rbp+rdx*8+0x0],eax
    inc    cl
    mov    eax, [rbp+rcx*8+0x0]
    shl    r8,0x8
    mov    r8b, [rbp+rbx*8+0x0]
    dec    r11b
    jne    .loop1
    bswap  r8
    xor    r8, [rsi-0x8]
    cmp    rsi,r9
    mov    [rdi-0x8],r8
    jle    .Lstart

.Lend:
    add    r9,0x8

.loop2:
    cmp    r9,rsi
    jle    .Lfinished
    add    dl,al
    mov    ebx, [rbp+rdx*8+0x0]
    mov    [rbp+rcx*8+0x0],ebx
    add    bl,al
    mov    [rbp+rdx*8+0x0],eax
    inc    cl
    mov    eax, [rbp+rcx*8+0x0]
    mov    r8b, [rbp+rbx*8+0x0]
    xor    r8b, [rsi]
    mov    [rdi],r8b
    inc    rsi
    inc    rdi
    jmp    .loop2

.Lfinished:
    dec    rcx
    mov    [rbp-0x8],dl
    mov    [rbp-0x10],cl

    ; Translate Linux->Windows x86_64 calling convention
    mov rax,       rcx
    mov rcx,       rdi
    mov rdi,       rax

    mov rax,       rdx
    mov rdx,       rsi
    mov rsi,       rax

    mov rax,       r8
    mov r8,        rdx
    mov rdx,       rax

    mov rax,       r9
    mov r9,        rcx
    mov rcx,       rax

    pop rdi
    pop rsi
    ; end translation

    pop    rbx
    pop    rbp
    ret

.L_RC4_end:
    nop
