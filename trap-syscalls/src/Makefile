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

default: trap-syscalls.so

LIBOPCODES_A ?= /usr/local/src/binutils-pic-build.hg/build/opcodes/libopcodes.a
LIBBFD_A ?= /usr/local/src/binutils-pic-build.hg/build/bfd/libbfd.a

ifeq ($(realpath $(LIBOPCODES_A)),)
$(error Could not find libopcodes.a! Please set LIBOPCODES_A)
endif
ifeq ($(realpath $(LIBBFD_A)),)
$(error Could not find libbfd.a! Please set LIBBFD_A)
endif

LDLIBS +=  $(LIBOPCODES_A) $(LIBBFD_A)

LIBC_ARCHIVE ?= -lc -ldl
LIBALLOCS ?= ../../../liballocs
SYSCALL_INTERFACE_FILE ?= ../../syscall-interfaces/scripts/linux-syscall-uniqtypes.c

C_SRC := $(wildcard *.c) $(SYSCALL_INTERFACE_FILE)
S_SRC := $(wildcard *.s)

OBJS := $(patsubst %.c,%.o,$(C_SRC)) $(patsubst %.s,%.o,$(S_SRC))

# Write the deps twice, once for each of the binaries we build.
# This is necessary because -MM by default only outputs a .o rule,
# whereas we don't build via .o, so want a rule for the whole binary.
.trap-syscalls.so.d: $(C_SRC)
	$(CC) -MM -MF /dev/stdout -MT trap-syscalls.so $(CFLAGS) $+ > "$@"

.trap-syscalls.d: $(C_SRC)
	$(CC) -MM -MF /dev/stdout -MT trap-syscalls -DEXECUTABLE $(CFLAGS) $+ > "$@"

ifneq ($(MAKECMDGOALS),clean)
-include .trap-syscalls.so.d
-include .trap-syscalls.d
endif

OFLAGS := -O2 
CFLAGS += -std=c99 -g 
CFLAGS += -Wall -Wno-unused-label -Wno-comment
CFLAGS += -O2

CFLAGS += -I $(LIBALLOCS)/include

# Don't build via .o, because we need different compile-time flags depending on 
# which target we're building.

# standalone program, for testing
trap-syscalls: $(C_SRC) $(S_SRC)
	$(CC) $(CFLAGS) -DEXECUTABLE -o "$@" $(C_SRC) $(S_SRC) $(LDFLAGS) $(LDLIBS)

trap-syscalls.so: CFLAGS += -fPIC -ffreestanding
trap-syscalls.so: LDLIBS := -Bstatic $(LDLIBS) $(LIBC_ARCHIVE)
trap-syscalls.so: $(C_SRC) $(S_SRC)
	echo C_SRC is $(C_SRC)
	echo S_SRC is $(S_SRC)
	$(CC) $(CFLAGS) -shared -o "$@" $(C_SRC) $(S_SRC) $(LDFLAGS) $(LDLIBS)


.PHONY: clean
clean:
	rm -f trap-syscalls trap-syscalls.so
	rm -f *.o
	rm -f .*.d
