        .section        .text
        .globl _start
_start:
        movq $39, %rax         # 39 is getpid
        movq _r_debug, %rdi    # create a dependency on the dynamic linker
        movq $0x0, %rdi
        syscall
        movq %rax, %rdi
        andq $0x7f, %rdi       # successful return in range 0..127
        movq $60, %rax         # exit
        syscall
