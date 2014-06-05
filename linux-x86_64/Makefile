CFLAGS += -g
CFLAGS += -Wall -Wextra -Wno-unused-label -Wno-unused-function -Wno-unused-parameter -Wno-unused-variable

# I can think of a few ways of achieving syscall interposition:
#
# - (in a dynamically linked binary) overriding the C library's wrappers
# - (in a statically linked binary)  ptrace(TRACE_ME)
# - (in either case)                 breakpointing on any syscall instruction (HMM, CFI-style problems)
#
# other things: vsyscall page, vdso
#
# Problem with libc: wrappers do not have publicly available names, nor
# consistent names.
#
# Problem with ptrace(TRACE_ME) -- you need a separate thread to trace from.
# BUT otherwise that might not be so bad.
#
# Problem with breakpointing: self-modifying code (JIT),

all: trap-syscalls.so

default: test trap-syscalls trap-syscalls.so

test-programs/hello-static: test-programs/hello.c
	$(CC) -static -o "$@" $(CFLAGS) "$<" $(LDFLAGS) $(LDLIBS)

test-programs/hello-dynamic: test-programs/hello.c
	$(CC) -o "$@" $(CFLAGS) "$<" $(LDFLAGS) $(LDLIBS)

# Turn off write permission on all executable pages. (HARD to do atomically)
# Scan them all and break on all syscall-making instruction bytes. (more atomicity)
# Install our breakpoint handler
# NOW we are bound to take a breakpoint before any *more* executable mappings are created.
# So we are a robust gatekeeper.

trap-syscalls: trap-syscalls.c do_syscall.c restorer.o
	$(CC) $(CFLAGS) -DEXECUTABLE -o "$@" $^ $(LDFLAGS) $(LDLIBS)

trap-syscalls.so: trap-syscalls.c do_syscall.c restorer.o
	$(CC) $(CFLAGS) -fPIC -shared -o "$@" $^ $(LDFLAGS) $(LDLIBS)

# true is the smallest dynamically linked executable we can build
test-programs/true: test-programs/true.s
	$(CC) -Wl,--export-dynamic -o "$@" -nostartfiles -nostdlib -Bdynamic "$<" /lib64/ld-linux-x86-64.so.2

test-programs/my_time: test-programs/my_time.s
	$(CC) -g -Wl,--export-dynamic -o "$@" -nostartfiles -nostdlib -Bdynamic "$<" /lib64/ld-linux-x86-64.so.2

test-programs/my_getpid: test-programs/my_getpid.s
	$(CC) -g -Wl,--export-dynamic -o "$@" -nostartfiles -nostdlib -Bdynamic "$<" /lib64/ld-linux-x86-64.so.2

.PHONY: clean
clean:
	rm -f sigill trap-syscalls trap-syscalls.so
	rm -f test-programs/hello-static test-programs/hello-dynamic test-programs/true
	rm -f do_syscall.o

.PHONY: test
test: trap-syscalls.so test-programs/true
	LD_PRELOAD=`pwd`/trap-syscalls.so ./test-programs/true

.PHONY: test-my_time
test-my_time: trap-syscalls.so test-programs/my_time
	LD_PRELOAD=`pwd`/trap-syscalls.so ./test-programs/my_time

.PHONY: test-my_time
test-my_getpid: trap-syscalls.so test-programs/my_getpid
	LD_PRELOAD=`pwd`/trap-syscalls.so ./test-programs/my_getpid
