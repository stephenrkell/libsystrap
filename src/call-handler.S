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
    jz 1f
    push %rax
    push %rcx
    mov __systrap_pre_handling(%rip), %r11
    call *%r11
    pop %rcx
    pop %rax
    1:
    # Do we have a replacement for this syscall?
    # XXX: this will buffer-overflow if %rax has a bogus value, or is x32-ABI.
    # One idea is to AND it with some bitmask that leaves twice as much value-space
    # as we need, then reserve the top half of the replacements table with a generic
    # "error" replacement. GAH. That doesn't work because it ANDs away high-order bits.
    # We probably want to count the leading zeros and slow-path if fewer than some N.
    lea replaced_syscalls(%rip), %r11
    cmp $0, (%r11,%rax,8)
    jz 3f
    push %rax   # must save the syscall number, in case post action wants it
    push %rcx
    mov (%r11,%rax,8), %r11
    call *%r11
    pop %rcx
    pop %r11    # Now the syscall number is moved into %r11
    # that's the replacement done -- now the return value is in %rax!
    jmp 4f
    3:
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
    # But we want to run the syscall with the exact same stack pointer as at the trap site.
    # See https://doc.liz6.com/en/systems-programming/02-system-call-abi/01-x86-64-system-call-abi
    # We could use the red zone, but then we will clobber it if the calling code is using it.
    # The psABI says
    #   "The Linux kernel does not honor the red zone (see 3.2.2) and therefore this area is
    #   not allowed to be used by kernel code. Kernel code should be compiled by GCC
    #   with the option -mno-red-zone."
    # ... which does not tell us whether the kernel clobbers this *or* whether user code can
    # assume it doesn't. I think "does not honor" really means "does not use" i.e. "does preserve".
    mov %rcx, -136(%rsp)    # XXX: is this OK? using space *below* the red zone
    mov %rax, -144(%rsp)    # XXX: is this OK? using space *below* the red zone
    syscall
    mov -144(%rsp), %r11    # Now the syscall number is in %r11, in case post action needs it
    mov -136(%rsp), %rcx
    # FIXME: what happens if we're doing clone() or clone3() with a new stack? %rcx is lost.
    # We could fall back to the stack-virtualised version of clone(), but ideally wouldn't.
    # Idea: pre-populate the new stack with our %rcx at -136(stack_top). This does
    # clobber some data on that initial stack; ideally we wouldn't. I'd take that hit for now.
    # The path where we're overwriting a non-zero word could be explicitly detected, although
    # falling back to the generic version wouldn't make sense becuase that clobbers
    # strictly more.
    4:
    cmpq $0, __systrap_post_handling(%rip)
    jz 5f
    # unlike before, %r11 is no longer scratch -- it contains the syscall number -- but
    # %rax is not scratch either as it contains the return value. To keep the calling
    # convention for raw pre- and post-handling wrappers the same, swap %rax and %r11
    xor %rax, %r11     # now %r11 is %oldr11 XOR %oldrax
    xor %r11, %rax     # now %rax is (%oldr11 XOR %oldrax XOR %oldrax) i.e. %oldr11 i.e. syscall number
    xor %rax, %r11     # now %r11 is (%oldr11 XOR %oldrax XOR %oldr11) i.e. %oldrax i.e. return value
    push %r11    # %oldrax  i.e. return value
    push %rax    # %oldr11  i.e. syscall number
    push %rcx
    # What's the *raw* way to communicate the return value of a system call
    # to the post-action? It's not %rax, which is the syscall number.
    # It has to be %r11. Indeed, a generic wrapper will put this in %rsi (second arg).
    # So now what is our scratch register?
    # It's not %r11 (retval) nor %rcx (site) nor %rax (nr).
    # HMM. Let's use the stack? Yes, this works.
    push __systrap_post_handling(%rip)
    call *0(%rsp)
    # no need to XOR-swap them back... just pop into different place
    pop %rcx    # dummy
    pop %rcx
    pop %r11    # gets the syscall number
    pop %rax    # gets the return value of the earlier syscall
    5:
    lea 2(%rcx), %rcx
    jmp *%rcx
