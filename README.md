# libsystrap and trap-syscalls

Interposing on system calls is useful for instrumentation or
"virtualisation"-like tools. The code in this repository lets you build
programs that can trap, reflect on and modify system calls as they
happen within a running program.

# Background

Traditionally there are a few ways of interposing on system calls

 - overriding the C library's wrappers
 - ptrace(TRACE_ME)
 - breakpointing on any syscall instruction

The code in this repository takes the latter approach. The former two
approaches both have drawbacks: not all syscalls go via libc wrappers,
and ptrace requires a separate thread to trace from.

The main drawback of the breakpointing approach is that you take a
double trap, increasing the overhead of syscalls (one trap to the
interposition code, the other to actually do the syscall). Also, you
must parse the instructions on all executable pages before you allow
them to run... handling self-modifying or dynamically generated code
(JIT) becomes tricky. We solve the latter by a bootstrapping approach: 
the JIT must create executable mappings by making system calls, which we
can intercept as they happen, and perform our breakpointing on the
dynamically generated instructions.

# libsystrap

This is a simple library to do the breakpointing and install a SIGILL
handler (which, unlike handling SIGTRAP, doesn't break debugging).

# trap-syscalls

This is a strace-like tool. It uses dwarfidl for scraping and
postprocessing the kernel DWARF, to get the system call names and type
signatures. It also uses libfootprints to walk the memory foorprints of
each call. This is overkill (and you'll have to build those repositories
to use it) but it serves as a useful example program. I should really
provide a "minimal dependencies" build mode for trap-syscalls, that
removes the need for libfootprints and DWARFy things, but it's not done
yet -- contributions welcome.

# Building

Unless you really know what you're doing, do `make' contrib/ first, and
cross your fingers.

Then do `make' in libsystrap, and then go on to use trap-syscalls as the
template for whatever you want to build.

The contrib/ directory's Makefile builds a big pile of dependencies. You
must use this! You can't just use stock libraries on your system,
because to pull the code into a preloadable libsystrap-enabled library,
it needs to be built as PIC archives. Usually, a stock build (of
binutils, glibc, opdis etc.) will build PIC shared objects and non-PIC
archives, so doesn't generate the right putputs. Anyway, the
contrib/Makefile should take care of all this.

At this stage I can't promise you won't have to hack the Makefiles
yourself....

# More detail

The logic in libsystrap is organised this way:

`trap.c` contains the logic of the trapping mechanism, its code is
standalone (does not rely on external libraries) and must run before any
other code. It replaces system calls in the original code with traps and
installs handling mechanisms.

`instr.c' actually does the instrumentation.

`do-syscall.c` is the interface between the previously mentioned trapping
mechanism and the user-provided handling tools.

`raw-syscalls.c` contains raw assembly implementations of the various
sytem calls required in the library itself, since it cannot rely on the C
library.

`restorer.c` is a copy of glibc's signal restorer needed to return into user
code.

