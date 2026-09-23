#include <sys/syscall.h>
#include "systrap-asm.h"

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
    # We land here if we need to do the actual syscall, because there's no replacement.
    # Some syscalls have special treatment.
    cmp $__NR_rt_sigreturn, %rax
    je 10f                    # just do the syscall; it never returns
    cmp $__NR_clone, %rax
    je 11f                    # special handling path
    cmp $__NR_clone3, %rax
    je 12f
    30:
    # Generic handling follows.
    # PROBLEM: the syscall will clobber %rcx which tells us our return address.
    # But we want to run the syscall with the exact same stack pointer as at the trap site.
    # See https://doc.liz6.com/en/systems-programming/02-system-call-abi/01-x86-64-system-call-abi
    #
    # Short answer: we use the red zone. This means we assume that the calling code, doing a
    # syscall, is not expecting the redzone to be preserved across a syscall.
    # That is consistent with the redzone as preserved across asynchronous interruptions only,
    # but not across calls. There may be some cursed code that expects it to be preserved
    # across syscalls but short of borrowing %gs (which some other cursed code may use),
    # this is the best bet.
    #
    # The psABI says
    #   "The Linux kernel does not honor the red zone (see 3.2.2) and therefore this area is
    #   not allowed to be used by kernel code. Kernel code should be compiled by GCC
    #   with the option -mno-red-zone."
    # ... which does not tell us whether the kernel clobbers this *or* whether user code can
    # assume it doesn't. I *believe* that "does not honor" really means "does not use" it,
    # i.e. the kernel does preserve the red zone. However, the vagueness of this language
    # is perhaps positive evidence that preserving the red zone across syscalls is not guaranteed.
    mov %rcx, -8(%rsp)
    mov %rax, -16(%rsp)
    10:                    # rt_sigreturn jumps in here since it doesn't need the redzone
    syscall
    mov -16(%rsp), %r11    # Now the syscall number is in %r11, in case post action needs it
    mov -8(%rsp), %rcx
    # Trap the case where sigreturn returns -- it shouldn't!
    # TODO: similar treatment here for exit_group and others? Or is any of this necessary?
    cmpq $__NR_rt_sigreturn, %r11
    je 7f
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
    # ... because we dropped it above, if present i.e. if a call got us here. So put it back!
    # Note that we adjusted it by 2 above.
    shl $1, %rcx               # clear the top bit
    shr $1, %rcx
    push %rcx                  # XXX: does this break CFI checks? Probably, at least in lcall case...
    retq
    7:
    # This is the "rt_sigreturn failed" path... print something then abort.
    mov $__NR_write, %rax
    mov $2, %rdi
    lea .Lrt_sigreturn_msg(%rip), %rsi
    mov $(.Lrt_sigreturn_msg_end - .Lrt_sigreturn_msg), %rdx
    syscall
    mov $__NR_exit, %rax
    mov $134, %rdi              # 128+SIGABRT
    syscall
.pushsection .rodata,"aMS",@progbits,1
.Lrt_sigreturn_msg:
    .ascii "Aborting: rt_sigreturn returned or unsupported clone() syscall\n"
.Lrt_sigreturn_msg_end: # we don't need the NUL terminator but include one anyway
    .byte 0
.popsection
    11:
    # This is the clone prep path.
    # Are we replacing the stack? YES, always I think -- NULL just means the kernel allocates it.
    # In the NULL case, we can skip this because the kernel copies the current stack,
    # including the stuff we save in the red zone.
    cmpq $0, %rsi
    je 30b
    # To be nice, we should test whether we're overwriting nonzero data
    cmpq $0, -8(%rsi)
    jne 15f
    cmpq $0, -16(%rsi)
    jne 15f
    # NOTE: we could share this code with the clone3 copy, below, but it has to pop %rsi.
    # Seems clearer to keep these code paths separate rather than merge and then pop conditionally.
    mov %rcx, -8(%rsi)      # %rsi points to "the topmost address of the new stack"
    mov %rax, -16(%rsi)
    jmp 30b
    12:
    # This is the clone3 prep path
    push %rsi
    push %rcx
    mov 40(%rdi), %rsi    # *bottom* address of new stack
    mov 48(%rdi), %rcx    # size of new stack
    add %rcx, %rsi        # now we're like clone: %rdx is the topmost address
    pop %rcx
    # As in clone, we skip ahead if the stack is null
    cmp $0, %rsi
    je 13f
    # To be nice, we should test whether we're overwriting nonzero data
    cmpq $0, -8(%rsi)
    jne 14f
    cmpq $0, -16(%rsi)
    jne 14f
    mov %rcx, -8(%rsi)
    mov %rax, -16(%rsi)
    13:
    pop %rsi
    jmp 30b
    14:
    # This is the unsupported clone case: the stack has been prepopulated.
    pop %rsi
    15:
    # what to do?
    jmp 7b   # jump to our abort path.
    # FIXME: distinguish the aborting cases
    # FIXME: pull the abort code down here, for i-cache reasons
    # FIXME: generally cache-optimise the code layout for the noop case (no replacement, no pre/post)
