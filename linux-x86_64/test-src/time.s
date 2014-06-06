        .section        .text
        .globl _start
_start:
        movq $201, %rax         # time
        movq _r_debug, %rdi     # create a dependency on the dynamic linker
        movq $0x0, %rdi
        syscall
        movq %rax, %rdi
        movq $60, %rax
        syscall
