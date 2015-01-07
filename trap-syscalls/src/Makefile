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

C_SRC := trap-syscalls.c do-syscall.c syscall-handlers.c raw-syscalls.c 
DEPS += $(patsubst %.c,.%.d,$(C_SRC))

S_SRC := restorer.s

# $(warning DEPS are $(DEPS))

OBJS := $(patsubst %.c,%.o,$(C_SRC)) $(patsubst %.s,%.o,$(S_SRC))

LIBC_ARCHIVE ?= -lc

# We want to use libopcodes, but don't want to link against it
# (to avoid libc dependency). Just vpath the source.
# LIBOPCODES_A ?= $(realpath $(wildcard /usr/local/src/binutils*)/builddir-single/opcodes/libopcodes.a)
# ifeq ($(LIBOPCODES_A),)
# $(error Could not find libopcodes.a! Please set LIBOPCODES_A)
# endif

$(DEPS): .%.d: %.c
	$(CC) -MM $(CFLAGS) "$<" > "$@"

ifneq ($(MAKECMDGOALS),clean)
-include $(DEPS)
endif

OFLAGS := -O2 
CFLAGS += -std=c99 -g 
CFLAGS += -Wall -Wno-unused-label -Wno-comment
CFLAGS += -O2

# Don't build via .o, because we need different compile-time flags depending on 
# which target we're building.

# standalone program, for testing
trap-syscalls: $(C_SRC) $(S_SRC)
	$(CC) $(CFLAGS) -DEXECUTABLE -o "$@" $^ $(LDFLAGS) $(LDLIBS)

trap-syscalls.so: CFLAGS += -fPIC -ffreestanding
trap-syscalls.so: LDLIBS := -Bstatic $(LDLIBS) $(LIBC_ARCHIVE)
trap-syscalls.so: $(C_SRC) $(S_SRC)
	$(CC) $(CFLAGS) -shared -o "$@" $^ $(LDFLAGS) $(LDLIBS)


.PHONY: clean
clean:
	rm -f trap-syscalls trap-syscalls.so
	rm -f *.o
	rm -f $(DEPS)
