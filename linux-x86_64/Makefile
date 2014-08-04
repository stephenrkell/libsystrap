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

default: test trap-syscalls trap-syscalls.so

SRC := trap-syscalls.c do_syscall.c syscall_handlers.c raw_syscalls.c
DEPS := $(patsubst %.c,.%.d,$(SRC))

$(DEPS): .%.d: %.c
	$(CC) -MM $(CFLAGS) "$<" > "$@"

-include $(DEPS)


WFLAGS := -Wall 								\
	 -Wextra 							\
	 -Wno-unused-label 						\
	 -Wno-unused-function 						\
	 -Wno-unused-parameter 						\
	 -Wno-unused-variable						\
	 -Wno-comment
OFLAGS := -O0 # XXX At this moment, any optimization breaks the code.
CFLAGS += $(WFLAGS) $(OFLAGS) -g

all: trap-syscalls.so

test-programs/hello-static: test-src/hello.c
	$(CC) -static -o "$@" $(CFLAGS) "$<" $(LDFLAGS) $(LDLIBS)

test-programs/hello-dynamic: test-src/hello.c
	$(CC) -o "$@" $(CFLAGS) "$<" $(LDFLAGS) $(LDLIBS)

# Turn off write permission on all executable pages. (HARD to do atomically)
# Scan them all and break on all syscall-making instruction bytes. (more atomicity)
# Install our breakpoint handler
# NOW we are bound to take a breakpoint before any *more* executable mappings are created.
# So we are a robust gatekeeper.

trap-syscalls: $(SRC) restorer.o
	$(CC) $(CFLAGS) -DEXECUTABLE -o "$@" $^ $(LDFLAGS) $(LDLIBS)

trap-syscalls.so: $(SRC) restorer.o
	$(CC) $(CFLAGS) -fPIC -shared -o "$@" $^ $(LDFLAGS) $(LDLIBS)

test-programs:
	mkdir -p test-programs

test-programs/%: test-src/%.c test-programs
	$(CC) -Wl,--export-dynamic -o $@ -nostartfiles -nostdlib -Bdynamic $< \
		/lib64/ld-linux-x86-64.so.2

test-programs/%: test-src/%.s test-programs
	$(CC) -Wl,--export-dynamic -o $@ -nostartfiles -nostdlib -Bdynamic $< \
		/lib64/ld-linux-x86-64.so.2

.PHONY: clean
clean:
	rm -f sigill trap-syscalls trap-syscalls.so
	rm -f test-programs/*
	rm -f do_syscall.o
	rm -f restorer.o

.PHONY: test
test: test-true

test-%: trap-syscalls.so test-programs/%
	LD_PRELOAD=`pwd`/trap-syscalls.so ./test-programs/$*
