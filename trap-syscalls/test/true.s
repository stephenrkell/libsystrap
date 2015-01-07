	.section	.text
	.globl _start
_start:
	movq $60, %rax		# exit
    movq _r_debug, %rdi # create a dependency on the dynamic linker
    movq $0x0, %rdi
	syscall
