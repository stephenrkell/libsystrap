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

