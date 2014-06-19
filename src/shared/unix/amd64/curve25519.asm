;/===-- curve25519.asm --------------------*- shared/unix/amd64 -*- ASM -*-===*/

; 2008, Google Inc.
; All rights reserved.
;
; Code released into the public domain
;
;###############################################################################
; curve25519-donna.s - an x86-64 bit implementation of curve25519. See the
; comments at the top of curve25519-donna.c
;
; Adam Langley <agl@imperialviolet.org>
;
; Derived from public domain C code by Daniel J. Bernstein <djb@cr.yp.to>
;
; More information about curve25519 can be found here
;   http://cr.yp.to/ecdh.html
;###############################################################################
;
; NOTE: Reassembled for NASM (original is gas)

;/===----------------------------------------------------------------------===*/

BITS 64

extern fmonty

global fmul:function hidden
global fsquare:function hidden
global fexpand:function hidden
global fcontract:function hidden
global freduce_coefficients:function hidden
global fscalar:function hidden
global fdifference_backwards:function hidden
global cmult:function hidden

section .text

fmul:
    push   rbx
    push   r12
    push   r13
    push   r14
    push   r15
    push   rdi
    mov    rcx,rsi
    mov    rsi,QWORD [rcx]
    mov    r8,QWORD  [rcx+0x8]
    mov    r9,QWORD  [rcx+0x10]
    mov    r10,QWORD  [rcx+0x18]
    mov    r11,QWORD  [rcx+0x20]
    mov    rdi,QWORD  [rdx]
    mov    r12,QWORD  [rdx+0x8]
    mov    r13,QWORD  [rdx+0x10]
    mov    r14,QWORD  [rdx+0x18]
    mov    r15,QWORD  [rdx+0x20]
    mov    rax,rsi
    mul    rdi
    movq   xmm0,rax
    movq   xmm1,rdx
    mov    rax,rsi
    mul    r12
    mov    rbx,rax
    mov    rcx,rdx
    mov    rax,r8
    mul    rdi
    add    rbx,rax
    adc    rcx,rdx
    movq   xmm2,rbx
    movq   xmm3,rcx
    mov    rax,r8
    mul    r12
    mov    rbx,rax
    mov    rcx,rdx
    mov    rax,rsi
    mul    r13
    add    rbx,rax
    adc    rcx,rdx
    mov    rax,r9
    mul    rdi
    add    rbx,rax
    adc    rcx,rdx
    movq   xmm4,rbx
    movq   xmm5,rcx
    mov    rax,rsi
    mul    r14
    mov    rbx,rax
    mov    rcx,rdx
    mov    rax,r10
    mul    rdi
    add    rbx,rax
    adc    rcx,rdx
    mov    rax,r8
    mul    r13
    add    rbx,rax
    adc    rcx,rdx
    mov    rax,r9
    mul    r12
    add    rbx,rax
    adc    rcx,rdx
    movq   xmm6,rbx
    movq   xmm7,rcx
    mov    rax,rsi
    mul    r15
    mov    rbx,rax
    mov    rcx,rdx
    mov    rax,r11
    mul    rdi
    add    rbx,rax
    adc    rcx,rdx
    mov    rax,r10
    mul    r12
    add    rbx,rax
    adc    rcx,rdx
    mov    rax,r8
    mul    r14
    add    rbx,rax
    adc    rcx,rdx
    mov    rax,r9
    mul    r13
    add    rbx,rax
    adc    rcx,rdx
    movq   xmm8,rbx
    movq   xmm9,rcx
    mov    rax,r11
    mul    r12
    mov    rbx,rax
    mov    rcx,rdx
    mov    rax,r8
    mul    r15
    add    rbx,rax
    adc    rcx,rdx
    mov    rax,r9
    mul    r14
    add    rbx,rax
    adc    rcx,rdx
    mov    rax,r10
    mul    r13
    add    rbx,rax
    adc    rcx,rdx
    movq   xmm10,rbx
    movq   xmm11,rcx
    mov    rax,r11
    mul    r13
    mov    rbx,rax
    mov    rcx,rdx
    mov    rax,r9
    mul    r15
    add    rbx,rax
    adc    rcx,rdx
    mov    rax,r10
    mul    r14
    add    rbx,rax
    adc    rcx,rdx
    movq   xmm12,rbx
    movq   xmm13,rcx
    mov    rax,r10
    mul    r15
    mov    rbx,rax
    mov    rcx,rdx
    mov    rax,r11
    mul    r14
    add    rbx,rax
    adc    rcx,rdx
    movq   xmm14,rbx
    movq   xmm15,rcx
    mov    rax,r11
    mul    r15

donna_reduce:
    mov    r15,0x13
    mov    r13,rdx
    mul    r15
    imul   r13,r15
    add    r13,rdx
    mov    r12,rax
    movq   rcx,xmm7
    movq   rbx,xmm6
    add    r12,rbx
    adc    r13,rcx
    movq   rax,xmm14
    mul    r15
    movq   r11,xmm15
    imul   r11,r15
    add    r11,rdx
    mov    r10,rax
    movq   rcx,xmm5
    movq   rbx,xmm4
    add    r10,rbx
    adc    r11,rcx
    movq   rax,xmm12
    mul    r15
    movq   r9,xmm13
    imul   r9,r15
    add    r9,rdx
    mov    r8,rax
    movq   rcx,xmm3
    movq   rbx,xmm2
    add    r8,rbx
    adc    r9,rcx
    movq   rax,xmm10
    mul    r15
    movq   rdi,xmm11
    imul   rdi,r15
    add    rdi,rdx
    mov    rsi,rax
    movq   rcx,xmm1
    movq   rbx,xmm0
    add    rsi,rbx
    adc    rdi,rcx
    movq   r15,xmm9
    movq   r14,xmm8
    mov    rbx,0x7ffffffffffff
    mov    rcx,0x13

.Lcoeffreduction:
    mov    rax,rsi
    shr    rsi,0x33
    shl    rdi,0xd
    or     rdi,rsi
    add    r8,rdi
    adc    r9,0x0
    xor    rdi,rdi
    mov    rsi,rax
    and    rsi,rbx
    mov    rax,r8
    shr    r8,0x33
    shl    r9,0xd
    or     r9,r8
    add    r10,r9
    adc    r11,0x0
    xor    r9,r9
    mov    r8,rax
    and    r8,rbx
    mov    rax,r10
    shr    r10,0x33
    shl    r11,0xd
    or     r11,r10
    add    r12,r11
    adc    r13,0x0
    xor    r11,r11
    mov    r10,rax
    and    r10,rbx
    mov    rax,r12
    shr    r12,0x33
    shl    r13,0xd
    or     r13,r12
    add    r14,r13
    adc    r15,0x0
    xor    r13,r13
    mov    r12,rax
    and    r12,rbx
    mov    rax,r14
    shr    r14,0x33
    shl    r15,0xd
    or     r15,r14
    imul   r15,r15,0x13
    add    rsi,r15
    adc    rdi,0x0
    xor    r15,r15
    mov    r14,rax
    and    r14,rbx
    mov    rax,rsi
    shr    rsi,0x33
    shl    rdi,0xd
    or     rdi,rsi
    add    r8,rdi
    adc    r9,0x0
    xor    rdi,rdi
    mov    rsi,rax
    and    rsi,rbx
    pop    rdi
    mov    QWORD  [rdi],rsi
    mov    QWORD  [rdi+0x8],r8
    mov    QWORD  [rdi+0x10],r10
    mov    QWORD  [rdi+0x18],r12
    mov    QWORD  [rdi+0x20],r14
    pop    r15
    pop    r14
    pop    r13
    pop    r12
    pop    rbx
    ret

fsquare:
    push   rbx
    push   r12
    push   r13
    push   r14
    push   r15
    push   rdi
    mov    rcx,rsi
    mov    rsi,QWORD  [rcx]
    mov    r8,QWORD  [rcx+0x8]
    mov    r9,QWORD  [rcx+0x10]
    mov    r10,QWORD  [rcx+0x18]
    mov    r11,QWORD  [rcx+0x20]
    mov    rax,rsi
    mul    rsi
    movq   xmm0,rax
    movq   xmm1,rdx
    mov    rax,rsi
    mul    r8
    shl    rax,1
    rcl    rdx,1
    movq   xmm2,rax
    movq   xmm3,rdx
    mov    rax,r8
    mul    r8
    mov    rbx,rax
    mov    rcx,rdx
    mov    rax,rsi
    mul    r9
    shl    rax,1
    rcl    rdx,1
    add    rbx,rax
    adc    rcx,rdx
    movq   xmm4,rbx
    movq   xmm5,rcx
    mov    rax,rsi
    mul    r10
    mov    rbx,rax
    mov    rcx,rdx
    shl    rbx,1
    rcl    rcx,1
    mov    rax,r8
    mul    r9
    shl    rax,1
    rcl    rdx,1
    add    rbx,rax
    adc    rcx,rdx
    movq   xmm6,rbx
    movq   xmm7,rcx
    mov    rax,rsi
    mul    r11
    mov    rbx,rax
    mov    rcx,rdx
    shl    rbx,1
    rcl    rcx,1
    mov    rax,r10
    mul    r8
    shl    rax,1
    rcl    rdx,1
    add    rbx,rax
    adc    rcx,rdx
    mov    rax,r9
    mul    r9
    add    rbx,rax
    adc    rcx,rdx
    movq   xmm8,rbx
    movq   xmm9,rcx
    mov    rax,r11
    mul    r8
    mov    rbx,rax
    mov    rcx,rdx
    shl    rbx,1
    rcl    rcx,1
    mov    rax,r9
    mul    r10
    shl    rax,1
    rcl    rdx,1
    add    rbx,rax
    adc    rcx,rdx
    movq   xmm10,rbx
    movq   xmm11,rcx
    mov    rax,r11
    mul    r9
    mov    rbx,rax
    mov    rcx,rdx
    shl    rbx,1
    rcl    rcx,1
    mov    rax,r10
    mul    r10
    add    rbx,rax
    adc    rcx,rdx
    movq   xmm12,rbx
    movq   xmm13,rcx
    mov    rax,r10
    mul    r11
    shl    rax,1
    rcl    rdx,1
    movq   xmm14,rax
    movq   xmm15,rdx
    mov    rax,r11
    mul    r11
    jmp    donna_reduce
    ;ret

fdifference_backwards:
    mov    rax,QWORD  [rsi]
    mov    r8,QWORD  [rsi+0x8]
    mov    r9,QWORD  [rsi+0x10]
    mov    r10,QWORD  [rsi+0x18]
    mov    r11,QWORD  [rsi+0x20]
    sub    rax,QWORD  [rdi]
    sub    r8,QWORD  [rdi+0x8]
    sub    r9,QWORD  [rdi+0x10]
    sub    r10,QWORD  [rdi+0x18]
    sub    r11,QWORD  [rdi+0x20]
    mov    rdx,0x8000000000000

.Lfdifference_backwards_loop:
    mov    rcx,rax
    sar    rcx,0x3f
    and    rcx,rdx
    add    rax,rcx
    shr    rcx,0x33
    sub    r8,rcx
    mov    rcx,r8
    sar    rcx,0x3f
    and    rcx,rdx
    add    r8,rcx
    shr    rcx,0x33
    sub    r9,rcx
    mov    rcx,r9
    sar    rcx,0x3f
    and    rcx,rdx
    add    r9,rcx
    shr    rcx,0x33
    sub    r10,rcx
    mov    rcx,r10
    sar    rcx,0x3f
    and    rcx,rdx
    add    r10,rcx
    shr    rcx,0x33
    sub    r11,rcx
    mov    rcx,r11
    sar    rcx,0x3f
    mov    rsi,rcx
    and    rcx,rdx
    add    r11,rcx
    and    rsi,0x13
    sub    rax,rsi
    mov    rcx,rax
    sar    rcx,0x3f
    and    rcx,rdx
    add    rax,rcx
    shr    rcx,0x33
    sub    r8,rcx
    mov    rcx,r8
    sar    rcx,0x3f
    and    rcx,rdx
    add    r8,rcx
    shr    rcx,0x33
    sub    r9,rcx
    mov    rcx,r9
    sar    rcx,0x3f
    and    rcx,rdx
    add    r9,rcx
    shr    rcx,0x33
    sub    r10,rcx
    mov    rcx,r10
    sar    rcx,0x3f
    and    rcx,rdx
    add    r10,rcx
    shr    rcx,0x33
    sub    r11,rcx
    mov    QWORD  [rdi],rax
    mov    QWORD  [rdi+0x8],r8
    mov    QWORD  [rdi+0x10],r9
    mov    QWORD  [rdi+0x18],r10
    mov    QWORD  [rdi+0x20],r11
    ret    

fscalar:
    mov    rcx,0x1db41
    mov    rax,QWORD  [rsi]
    mul    rcx
    shl    rdx,0xd
    mov    r8,rdx
    mov    r9,rax
    mov    rax,QWORD  [rsi+0x8]
    mul    rcx
    add    rax,r8
    shl    rdx,0xd
    mov    r8,rdx
    mov    QWORD  [rdi+0x8],rax
    mov    rax,QWORD  [rsi+0x10]
    mul    rcx
    add    rax,r8
    shl    rdx,0xd
    mov    r8,rdx
    mov    QWORD  [rdi+0x10],rax
    mov    rax,QWORD  [rsi+0x18]
    mul    rcx
    add    rax,r8
    shl    rdx,0xd
    mov    r8,rdx
    mov    QWORD  [rdi+0x18],rax
    mov    rax,QWORD  [rsi+0x20]
    mul    rcx
    add    rax,r8
    mov    QWORD  [rdi+0x20],rax
    shl    rdx,0xd
    mov    rcx,0x13
    mov    rax,rdx
    mul    rcx
    add    r9,rax
    mov    QWORD  [rdi],r9
    ret    

freduce_coefficients:
    push   r12
    mov    rcx,0x7ffffffffffff
    mov    rdx,0x13
    mov    r8,QWORD  [rdi]
    mov    r9,QWORD  [rdi+0x8]
    mov    r10,QWORD  [rdi+0x10]
    mov    r11,QWORD  [rdi+0x18]
    mov    r12,QWORD  [rdi+0x20]

.Lcarrychain_:
    mov    rax,r8
    shr    rax,0x33
    add    r9,rax
    and    r8,rcx
    mov    rax,r9
    shr    rax,0x33
    add    r10,rax
    and    r9,rcx
    mov    rax,r10
    shr    rax,0x33
    add    r11,rax
    and    r10,rcx
    mov    rax,r11
    shr    rax,0x33
    add    r12,rax
    and    r11,rcx
    mov    rax,r12
    shr    rax,0x33
    imul   rax,rax,0x13
    add    r8,rax
    and    r12,rcx
    mov    QWORD  [rdi],r8
    mov    QWORD  [rdi+0x8],r9
    mov    QWORD  [rdi+0x10],r10
    mov    QWORD  [rdi+0x18],r11
    mov    QWORD  [rdi+0x20],r12
    pop    r12
    ret

fexpand:
    mov    rdx,0x7ffffffffffff
    mov    rax,QWORD  [rsi]
    and    rax,rdx
    mov    QWORD  [rdi],rax
    mov    rax,QWORD  [rsi+0x6]
    shr    rax,0x3
    and    rax,rdx
    mov    QWORD  [rdi+0x8],rax
    mov    rax,QWORD  [rsi+0xc]
    shr    rax,0x6
    and    rax,rdx
    mov    QWORD  [rdi+0x10],rax
    mov    rax,QWORD  [rsi+0x13]
    shr    rax,1
    and    rax,rdx
    mov    QWORD  [rdi+0x18],rax
    mov    rax,QWORD  [rsi+0x19]
    shr    rax,0x4
    and    rax,rdx
    mov    QWORD  [rdi+0x20],rax
    ret

fcontract:
    mov    rax,QWORD  [rsi]
    mov    rdx,QWORD  [rsi+0x8]
    mov    r8,QWORD  [rsi+0x10]
    mov    r9,QWORD  [rsi+0x18]
    mov    r10,QWORD  [rsi+0x20]
    mov    rcx,rdx
    shl    rcx,0x33
    or     rax,rcx
    mov    QWORD  [rdi],rax
    shr    rdx,0xd
    mov    rcx,r8
    shl    rcx,0x26
    or     rdx,rcx
    mov    QWORD  [rdi+0x8],rdx
    shr    r8,0x1a
    mov    rcx,r9
    shl    rcx,0x19
    or     r8,rcx
    mov    QWORD  [rdi+0x10],r8
    shr    r9,0x27
    shl    r10,0xc
    or     r9,r10
    mov    QWORD  [rdi+0x18],r9
    ret

cmult:
    push   rbp
    push   r13
    push   r14
    mov    rbp,rsp
    mov    r8,0x3f
    not    r8
    and    rsp,r8
    mov    r13,rdx
    mov    r14,rcx
    sub    rsp,0x200
    mov    rax,QWORD  [rcx]
    mov    QWORD  [rsp],rax
    mov    r8,QWORD  [rcx+0x8]
    mov    QWORD  [rsp+0x8],r8
    mov    r9,QWORD  [rcx+0x10]
    mov    QWORD  [rsp+0x10],r9
    mov    r10,QWORD  [rcx+0x18]
    mov    QWORD  [rsp+0x18],r10
    mov    r11,QWORD  [rcx+0x20]
    mov    QWORD  [rsp+0x20],r11
    mov    QWORD  [rsp+0x40],0x1
    mov    QWORD  [rsp+0x48],0x0
    mov    QWORD  [rsp+0x50],0x0
    mov    QWORD  [rsp+0x58],0x0
    mov    QWORD  [rsp+0x60],0x0
    mov    QWORD  [rsp+0x80],0x1
    mov    QWORD  [rsp+0x88],0x0
    mov    QWORD  [rsp+0x90],0x0
    mov    QWORD  [rsp+0x98],0x0
    mov    QWORD  [rsp+0xa0],0x0
    mov    QWORD  [rsp+0xc0],0x0
    mov    QWORD  [rsp+0xc8],0x0
    mov    QWORD  [rsp+0xd0],0x0
    mov    QWORD  [rsp+0xd8],0x0
    mov    QWORD  [rsp+0xe0],0x0
    push   rbx
    push   r12
    push   r15
    push   rdi
    push   rsi
    mov    r12,0x100
    mov    rbx,0x20

.Lcmult_loop_outer:
    sub    rbx,0x8
    mov    r15,QWORD  [r13+rbx*1+0x0]
    shl    rbx,0x20
    or     rbx,0x40

.Lcmult_loop_inner:
    mov    r8,0x80
    xor    r9,r9
    bt     r15,0x3f
    cmovb  r9,r8
    mov    r8,r9
    xor    r8,0x80
    shl    r15,1
    mov    r11,r12
    xor    r11,0x100
    lea    rdi,[rsp+r12*1+0x28]
    mov    rsi,rdi
    lea    rdx,[rsp+r11*1+0x28]
    mov    rcx,rdx
    add    rdi,r8
    add    rsi,r9
    add    rdx,r8
    add    rcx,r9
    mov    r8,r14
    call   fmonty
    xor    r12,0x100
    dec    rbx
    cmp    ebx,0x0
    jne    .Lcmult_loop_inner
    shr    rbx,0x20
    cmp    rbx,0x0
    jne    .Lcmult_loop_outer
    pop    rsi
    pop    rdi
    pop    r15
    pop    r12
    pop    rbx
    lea    r8,[rsp+0x80]
    mov    rax,QWORD  [r8]
    mov    QWORD  [rdi],rax
    mov    rax,QWORD  [r8+0x8]
    mov    QWORD  [rdi+0x8],rax
    mov    rax,QWORD  [r8+0x10]
    mov    QWORD  [rdi+0x10],rax
    mov    rax,QWORD  [r8+0x18]
    mov    QWORD  [rdi+0x18],rax
    mov    rax,QWORD  [r8+0x20]
    mov    QWORD  [rdi+0x20],rax
    mov    rax,QWORD  [r8+0x40]
    mov    QWORD  [rsi],rax
    mov    rax,QWORD  [r8+0x48]
    mov    QWORD  [rsi+0x8],rax
    mov    rax,QWORD  [r8+0x50]
    mov    QWORD  [rsi+0x10],rax
    mov    rax,QWORD  [r8+0x58]
    mov    QWORD  [rsi+0x18],rax
    mov    rax,QWORD  [r8+0x60]
    mov    QWORD  [rsi+0x20],rax
    mov    rsp,rbp
    pop    r14
    pop    r13
    pop    rbp
    ret
