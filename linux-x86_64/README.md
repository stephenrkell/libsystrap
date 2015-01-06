# A few ways of interposing on system calls

 - (in a dynamically linked binary) overriding the C library's wrappers
 - (in a statically linked binary)  ptrace(TRACE_ME)
 - (in either case)                 breakpointing on any syscall instruction (HMM, CFI-style problems)

Problem with libc: wrappers do not have publicly available names, nor consistent names.
Problem with ptrace(TRACE_ME) -- you need a separate thread to trace from.
Problem with breakpointing: must handle self-modifying code (JIT). 
We choose the breakpointing approach. The JIT problem is solved by a bootstrapping approach: 
the JIT must create executable mappings by making system calls, which we can intercept as they happen, 
and perform our breakpointing on the dynamically generated instructions.


# Trap-syscall

This is a pre-loaded library aiming at allowing a user to run a binary
while keeping control of the interactions between the program and the
operating system.

The logic is organised this way:

`trap-syscall.c` contains the logic of the trapping mechanism, its code is
standalone (does not rely on external libraries) and must run before any
other code. It replaces system calls in the original code with traps and
installs handling mechanisms.

`do-syscall.c` is the interface between the previously mentioned trapping
mechanism and the user-provided handling tools.

`raw-syscalls.c` contains raw assembly implementations of the various
sytem calls required in the library itself, since it cannot rely on the C
library.

`restorer.s` is a small assembly snippet required for the signal handler
mechanism in trap-syscall to work properly.


`syscall-handlers.{c,h}` has some hand-written interposing examples -
parts of this should be replaced by C generated from the .ml data
produced by the code in syscall-dsl.


`make` here builds and runs some test using this syscall-handlers on
the `true` program.

