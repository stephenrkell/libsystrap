# libsystrap and trace-syscalls

Interposing on system calls is useful for instrumentation or
"virtualisation"-like tools. The code in this repository lets you build
programs that can trap, reflect on and modify system calls as they
happen within a running program. It consists of a library (libsystrap)
and an example tool (trace-syscalls.so, a preloadable tracing library).

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

# trace-syscalls.so

This is a strace-like tool.

# trace-sysfoot.so

This is an extension of trace-syscalls that also collects further
semantic information about syscalls, including (thanks to dwarfidl) for
system call names and type signatures scraped from the kernel DWARF. It
also uses libfootprints to walk the memory foorprints of each call. This
will soon be split into its own repository, since it has many more
dependencies and is very fragile/experimental at present.

# Building

Unless you really know what you're doing, do `make' contrib/ first, and
cross your fingers.

Then do `make' in src/, and then in example/. You can use trace-syscalls
as a starting point for whatever you want to build.

The contrib/ directory's Makefile builds a big pile of dependencies. You
must use this! You can't just use stock libraries on your system,
because to pull the code into a preloadable libsystrap-enabled library,
it needs to be built as PIC archives. Usually, a Debian-style stock
packaging (of glibc, say) will build PIC shared objects and non-PIC
archives -- i.e. not the PIC achive we need. Anyway, the
contrib/Makefile should take care of all this.

# More detail

Some notes on the contents of libsystrap:

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

