#include <sys/syscall.h>
#include "systrap-asm.h"

# XXX: concurrency bug. This code pathway is
# prone to crashes in code that handles signals. WHY?
# Previously, during a SIGILL handler, some signals were masked. WHICH?
# And what difference did that make? Why would taking a signal during this
# path, say, cause a problem? Is this an async safety issue?
# 
# If we use stdio during the handler, ... do we?
#
# Or let's imagine that we're interrupted by a user-handled-signal / sigreturn pair.
# That's a *user* sigreturn on the same thread. So we will trap it! What happens?
# We take a SIGILL then early-sigreturn to *this* path (another activation thereof)...
# ... which will do the sigreturn with the pre-action
# on behalf of the *user* sigreturning code
# and the moment we do that sigreturn, we're back at the *signalled-at* code,
# which is us!
# All of this would seem to work fine. But there is definitely an async-signal-safety issue,
# unless we abstain from stdio. Which we do! So maybe async-signal-safety doesn't explain it,
# unless there are rogue stdio calls going on.
# Now I can't reproduce the problem.
#
# Could we be clobbering a register if we are interrupted in the wrong place?
# I think I saw 0xfff...fffc being jumped to or accessed.
#
# Could it simply be our AVX/SSE2 known weakness?
# MAYBE. FIX THIS!
# Also we don't yet handle clone()... do this below. It's only a few instructions.

.text
.globl __systrap_call_handler_with_retaddr_restore
__systrap_call_handler_with_retaddr_restore:
    # we need to search our return addresses by the lower 32 bits of 0(%rsp)...
    # we use an open-"hashing" lookup where hash functions are just taking
    # 12 bits from the address, starting with [0,11] and if necessary, sliding up
    # one by one. This deals with hash collisions but not data collisions... if
    # two same-lower-32 addresses are trap sites, we have to trap one or both of
    # them by some other means.
    # free up one more register
    push %rdx
    mov __systrap_lcall_retaddrs@gotpcrel(%rip), %r11
    xor %rcx, %rcx      # %rcx is a counter, 0 to 30 (potentially!)
    0:
    movl 8(%rsp), %edx         # %edx is the 32-bit word
    sar %cl, %edx              # %edx is now the shifted 32-bit word
    and $0xfff, %edx           # ... now just 12 bits of it
    mov (%r11, %rdx, 8), %rdx  # now %rdx is the 64-bit table entry...
    cmpl %edx, 8(%rsp)         # ... do its lower 32 match?
    je 2f                      # match / success... we have left the 64-bit value in %rdx
    inc %cl
    cmp $21, %cl               # We have 21 hash functions: [0,11], [1,12], ..., [20,31]
    je 1f                      # our counter hit 21 -- lookup failed
    jmp 0b
    1:
    # hash lookup failure... what to do? just abort for now
    jmp 6f
    2:
    lea -6(%rdx), %rcx         # we needed %rcx for the shift, but it's free now
                               # lcalls are 6 bytes long, and the *site* addr is what we want in %rcx
    rol $1, %rcx               # set the top bit in %rcx
    or $1, %rcx
    ror $1, %rcx
    pop %rdx
    # We got here from a call. But we want our handler to run with the exact same %rsp
    # as at the system call site. So drop the on-stack return address.
    add $8, %rsp
# fall through!
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
    # To avoid buffer-overflow if %rax has a bogus value, or is x32-ABI, count leading zeroes...
    # we do this by "bit-scan reverse" which gives us the bit idx of the most significant 1 set.
    # If it's pos N (0..63), then we'd better have at least 2^(N+1) syscalls
    # i.e. pos must be strictly < LOG_NSYSCALLS.
    # XX: might be faster to do a simple right-shift and jnz
    mov %rax, %r11
    shr $LOG_NSYSCALLS, %r11
    cmp $0, %r11
    jnz 3f                     # the top bits should be zero if we want to index using %rax
    2:
    lea replaced_syscalls(%rip), %r11
    cmpq $0, (%r11,%rax,8)
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
    mov %rcx, -8(%rsp)
    mov %rax, -16(%rsp)
    syscall
    mov -16(%rsp), %r11    # Now the syscall number is in %r11, in case post action needs it
    mov -8(%rsp), %rcx
    # What happens if the syscall is a sigreturn? We don't get to the post-action, but
    # otherwise I think it *should* all go fine. Trap the case where sigreturn returns.
    cmpq $__NR_rt_sigreturn, %r11
    je 7f
    # TODO: similar treatment here for exit_group and others? Or is any of this necessary?
    # FIXME: what happens if we're doing clone() or clone3() with a new stack? %rcx and %rax are lost.
    # XXX: clone seems to work anyway? could be because child_stack=0
    # Does it matter that %rax is lost? Yes, post-action might want to print it.
    # Does it matter that %rcx is lost? Yes, it's the site in user code that we must return to (+n).
    #
    # We could fall back to the stack-virtualised version of clone(), but ideally wouldn't.
    # Idea: pre-populate the new stack with our %rcx at -136(stack_top). This does
    # clobber some data on that initial stack; ideally we wouldn't. I'd take that hit for now.
    # The path where we're overwriting a non-zero word could be explicitly detected, although
    # falling back to the generic version wouldn't make sense because that clobbers
    # strictly more.
    4:
    cmpq $0, __systrap_post_handling(%rip)
    jz 5f
    # As we arrive here, %rax holds the syscall return value and %r11 the syscall number.
    # Unlike before, %r11 is not scratch. Nor is %rax; it contains the return value.
    # To keep the calling convention for raw pre- and post-handling wrappers the same,
    # swap %rax and %r11... in other words we still pass the syscall number in %rax;
    # return value goes in %r11.
    push %r11
    push %rax
    mov 0(%rsp), %r11       # %oldrax  i.e. return value
    mov 8(%rsp), %rax       # %oldr11  i.e. syscall number
    push %rcx
    # Now what is our scratch register? We don't have one!
    # It's not %r11 (retval) nor %rcx (site) nor %rax (nr).
    # Let's use the stack? Yes, this works.
    push __systrap_post_handling(%rip)
    call *0(%rsp)
    add $8, %rsp    # drop the address we pushed
    pop %rcx
    pop %rax
    pop %r11
    5:
    # XXX: if we got here by an lcall, the return address (plus some offset!) is on the stack
    # but we put it in %rcx earlier when we fixed it up. We should clean up
    # the stack, but also, do the appropriate kind of ret/jmp since otherwise we
    # may defeat control-flow integrity mechanisms (CEt / endbr). Luckily, the lcall
    # pathway has some extra instructions at the top. Maybe borrow the top bit of %rcx?
    add $2, %rcx
    # Since we used 'add' not 'lea', there is a flag telling us whether %rcx is negative...
    js 6f
    jmp *%rcx
    6:
    # This is the return path... a short return for a long call.
    # We *don't* have the return address on the stack yet...
    # ... because we dropped it above, if a call got us here. So put it back!
    # Note that we adjusted it by 2 above.
    shl $1, %rcx               # clear the top bit
    shr $1, %rcx
    # ... so put it back.
    push %rcx
    retq
    7:
    # This is the "rt_sigreturn failed" path... print something then abort.
    # FIXME: assembler is generating relocs the linker barfs on, I think at the lea
    # below. Comment out for now.
    # mov $__NR_write, %rax
    # mov $2, %rdi
    # lea Lrt_sigreturn_msg, %rsi
    # mov $(Lrt_sigreturn_msg_end - Lrt_sigreturn_msg_end), %rdx
    # syscall
    mov $__NR_exit, %rax
    mov $-134, %rdi       # successful return in range 0..127
    syscall
.pushsection ".rodata"
Lrt_sigreturn_msg:
    .ascii "Aborting: rt_sigreturn returned\n"
Lrt_sigreturn_msg_end:
.popsection
