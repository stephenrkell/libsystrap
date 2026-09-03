.text
.globl __systrap_call_handler
__systrap_call_handler:
    # We may have been jumped to from a signal handler, which exited into us,
    # or directly-ish from a fallthrough path above (TODO).
    # We have the trap site in %rcx.
    # If we have no generic handlers defined, we can execute a straight replacement.
    cmpq $0, __systrap_pre_handling(%rip)
    jnz Lslow_path
    cmpq $0, __systrap_post_handling(%rip)
    jnz Lslow_path
    # Do we have a replacement for this syscall?
    lea replaced_syscalls(%rip), %r11
    cmp $0, (%r11,%rax,8)
    jnz Lslow_path
    # If we got here, we have no replacement so we can just do the syscall.
    # PROBLEM: the syscall will clobber %rcx which is our return address.
    # See https://doc.liz6.com/en/systems-programming/02-system-call-abi/01-x86-64-system-call-abi
    # We could use the red zone, but then we will clobber it if the calling code is using it.
    # The psABI says
    #   "The Linux kernel does not honor the red zone (see 3.2.2) and therefore this area is
    #   not allowed to be used by kernel code. Kernel code should be compiled by GCC
    #   with the option -mno-red-zone."
    # ... which does not tell us whether the kernel clobbers this *or* whether user code can
    # assume it doesn't.
    mov %rcx, -136(%rsp)    # XXX: is this OK? using space *below* the red zone
    syscall
    mov -136(%rsp), %rcx

    # XXX: can't do this! %rcx is clobbered.
    # Even if we use the red zone, what happens if we do clone()? We could fall back to the
    # stack-virtualised version of that. It's a shame to do so. Some registers *are* preserved
    # across syscalls, so there should be a way to do it? Albeit specialized to clone()?
    lea 2(%rcx), %rcx
    jmp %rcx
Lslow_path:
    # We build a struct generic_syscall right here on the stack. context ptr is null.
    # ibcs_sigframe *context
    # void *site;
    # int syscall_number;
    # long int args[6];
    push %r9     # args[5]
    push %r8     # args[4]
    push %r10    # args[3]
    push %rdx    # args[2]
    push %rsi    # args[1]
    push %rdi    # args[0]
    push %rax    # syscall_number
    push %rcx    # site
    push $0      # signal context
    # Of the main general-purpose x86-64 registers, we've now
    # pushed all those that are callee-save in the syscall ABI
    # and not also callee-save in the System V ABI.
    # So it's OK if the code we jump to next trashes them, as long
    # as we come back here and restore them.
    # BUT
    # The code we jump to next is not arbitrary SysV: we have not
    # saved the floating-point or SSE or AVX registers.
    # But it should be programmable in C with the right pragmas
    # and options for disabling those extensions.
    mov %rsp, %rdi
    # Now the regs we saved above are usable as scratch... we will
    # restore them. Don't use others, even %r12! We need to preserve
    # our caller's value of it.
    push %rbp         # we'll restore this shortly... we use %rbp to remember the #bytes of stack adjustment...
    and $0xf, %rbp    # ... since %rbp is our only available SysV-callee-saved register!
    sub %rbp, %rsp    # align stack
    mov $0, 0(%rsp)   # ensure any space freed up is zeroed -- if none, we just re-zero the $0 pushed earlier
    # BUT WAIT -- the generic syscall needs to know the original %rsp somehow
    # when it is to implement clone(). Maybe it needs to go in the args?
    # since sigreturn and clone are essentially using %rsp as an arg.
    callq __systrap_call_handler_slow
    add %rbp, %rsp    # undo stack alignment
    pop %rbp
    add $8, %rsp      # pop the zero ('context')
    pop %rcx          # pop the real %rcx ('site')
    add $8, %rsp      # no longer syscall_number; %rax has the return value, so leave it there
    pop %rdi
    pop %rsi
    pop %rdx
    pop %r10
    pop %r8
    pop %r9
    lea 0x2(%rcx), %rcx
    jmp *%rcx
