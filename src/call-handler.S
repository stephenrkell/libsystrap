.text
.globl __systrap_call_handler
__systrap_call_handler:
    # We have the trap site in %rcx, but other registers are the same as
    # at the intended site of the intended system call. %r11 is clobberable.
    #
    # We may have been jumped to from a signal handler, which exited into us,
    # or directly-ish from a fallthrough path above (TODO).
    #
    # If we have no generic handlers defined, we can execute a straight replacement.
    cmpq $0, __systrap_pre_handling(%rip)
    jnz Lslow_path
    cmpq $0, __systrap_post_handling(%rip)
    jnz Lslow_path
    # Do we have a replacement for this syscall?
    # XXX: this will buffer-overflow if %rax has a bogus value, or is x32-ABI.
    # One idea is to AND it with some bitmask that leaves twice as much value-space
    # as we need, then reserve the top half of the replacements table with a generic
    # "error" replacement. GAH. That doesn't work because it ANDs away high-order bits.
    # We probably want to count the leading zeros and slow-path if fewer than some N.
    lea replaced_syscalls(%rip), %r11
    cmp $0, (%r11,%rax,8)
    jnz Lslow_path
    # TODO: instead of jumping to a slow path if non-zero, just jump to the
    # handler! Then macroise the slow path written below, so that we can wrap
    # any "raw handler" or "asm handler" in it. There are a few flavours of
    # handler we can imagine...
    # - "raw" or "asm": takes full responsibility for its register footprint; returns to original site?
    # - nongeneric "scalarint-only" / "noextension" (good name needed!): can be written in C
    #     after disabling vector and floating-point extensions, but has the plain syscall signature
    #     rather than a generic / packed version.
    # - generic version of the same
    # - nongeneric wrapped in a full xsave
    # - generic wrapped in a full xsave
    # TODO: figure out which of these can/should return to the caller vs returning here
    # TODO: what if we have pre/post handlers but a *non*-generic replacement? We still
    # have to build the packed version. One solution would be to make the pre/post-handlers
    # themselves non-generic by default, and force the user to wrap them if they want this. YES.
    # The generic-or-no, fpavail-or-no choices are orthogonal.

    # If we got here, we have no replacement so we can just do the syscall.
    # PROBLEM: the syscall will clobber %rcx which is our return address.
    # See https://doc.liz6.com/en/systems-programming/02-system-call-abi/01-x86-64-system-call-abi
    # We could use the red zone, but then we will clobber it if the calling code is using it.
    # The psABI says
    #   "The Linux kernel does not honor the red zone (see 3.2.2) and therefore this area is
    #   not allowed to be used by kernel code. Kernel code should be compiled by GCC
    #   with the option -mno-red-zone."
    # ... which does not tell us whether the kernel clobbers this *or* whether user code can
    # assume it doesn't. I think "does not honor" really means "does not use" i.e. "does preserve".
    mov %rcx, -136(%rsp)    # XXX: is this OK? using space *below* the red zone
    syscall
    mov -136(%rsp), %rcx
    # FIXME: what happens if we're doing clone() or clone3() with a new stack? %rcx is lost.
    # We could fall back to the stack-virtualised version of clone(), but ideally wouldn't.
    # Idea: pre-populate the new stack with our %rcx at -136(stack_top). This does
    # clobber some data on that initial stack; ideally we wouldn't. I'd take that hit for now.
    
    lea 2(%rcx), %rcx
    jmp *%rcx
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
