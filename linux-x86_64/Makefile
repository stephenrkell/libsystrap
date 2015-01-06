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

SRC := trap-syscalls.c do-syscall.c syscall-handlers.c raw-syscalls.c
DEPS := $(patsubst %.c,.%.d,$(SRC))
$(warning DEPS are $(DEPS))

LIBC_ARCHIVE ?= -lc
LD_SO ?= /lib64/ld-linux-x86-64.so.2

# We want to use libopcodes, but don't want to link against it
# (to avoid libc dependency). Just vpath the source.
LIBOPCODES_A ?= $(realpath $(wildcard /usr/local/src/binutils*)/builddir-single/opcodes/libopcodes.a)
ifeq ($(LIBOPCODES_A),)
$(error Could not find libopcodes.a! Please set LIBOPCODES_A)
endif

$(DEPS): .%.d: %.c
	$(CC) -MM $(CFLAGS) "$<" > "$@"

-include $(DEPS)

WFLAGS := -Wall 							\
	 -Wextra 							\
	 -Wno-unused-label 						\
	 -Wno-unused-function 						\
	 -Wno-unused-parameter 						\
	 -Wno-unused-variable						\
	 -Wno-comment
OFLAGS := -O2 
CFLAGS += -std=c99 $(WFLAGS) $(OFLAGS) -g

all: trap-syscalls.so


# standalone program, for testing
trap-syscalls: $(SRC) restorer.o
	$(CC) $(CFLAGS) -DEXECUTABLE -o "$@" $^ $(LDFLAGS) $(LDLIBS)

trap-syscalls.so: $(SRC) restorer.o
	$(CC) $(CFLAGS) -fPIC -ffreestanding -shared -o "$@" $^ $(LDFLAGS) -Bstatic $(LDLIBS) $(LIBC_ARCHIVE)

test-programs:
	mkdir -p test-programs

test-programs/%: test-src/%.c test-programs
	$(CC) -Wl,--export-dynamic -o $@ -nostartfiles -nostdlib -Bdynamic $< \
		$(LD_SO)

test-programs/true: LDLIBS += $(LD_SO)
test-programs/true: LDFLAGS += -nostartfiles -nostdlib

test-programs/%: test-src/%.s test-programs
	$(CC) $(CFLAGS) -o "$@" "$<" $(LDFLAGS) $(LDLIBS)

test-programs/%: test-src/%.c test-programs
	$(CC) -ffreestanding $(CFLAGS) -o "$@" "$<" $(LDFLAGS) $(LDLIBS)

# statically linked binaries can't do LD_PRELOAD, so are not a suitable test case
# test-programs/hello-static: test-src/hello.c
# 	$(CC) -static -o "$@" $(CFLAGS) "$<" $(LDFLAGS) $(LDLIBS)

test-programs/hello-dynamic: test-src/hello.c
	$(CC) -o "$@" $(CFLAGS) "$<" $(LDFLAGS) $(LDLIBS)

.PHONY: clean
clean:
	rm -f sigill trap-syscalls trap-syscalls.so
	rm -f test-programs/*
	rm -f do-syscall.o
	rm -f restorer.o

.PHONY: test
test: test-true | trap-syscalls.so

test-%: trap-syscalls.so test-programs/%
	./run-with-trap-syscalls.sh ./test-programs/$*
