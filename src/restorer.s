	.section	.text
	.globl restore_rt
restore_rt:
	movq $0xf, %rax
	syscall
	nopl   0x0(%rax)
