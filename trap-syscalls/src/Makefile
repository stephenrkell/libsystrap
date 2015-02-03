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

#LIBOPCODES_A ?= /usr/local/src/binutils-pic-build.hg/build/opcodes/libopcodes.a
#LIBBFD_A ?= /usr/local/src/binutils-pic-build.hg/build/bfd/libbfd.a
#
#ifeq ($(realpath $(LIBOPCODES_A)),)
#$(error Could not find libopcodes.a! Please set LIBOPCODES_A)
#endif
#ifeq ($(realpath $(LIBBFD_A)),)
#$(error Could not find libbfd.a! Please set LIBBFD_A)
#endif
#
#LDLIBS +=  $(LIBOPCODES_A) $(LIBBFD_A)

THIS_MAKEFILE ?= $(lastword $(MAKEFILE_LIST))

LIBALLOCS ?= ../../../liballocs
LIBC_A ?= -lc -ldl

# LLVM_CXXFLAGS ?= $(shell llvm-config --cxxflags)
# LIBLLVM_ARCHIVE ?= -lllvm_X86 -lllvm
# LIBSTDCXX_ARCHIVE ?= -lstdc++

LIBOPDIS_A ?= -lopdis
LIBOPCODES_A ?= -lopcodes
LIBBFD_A ?= -lbfd
LIBIBERTY_A ?= -liberty

ZLIB_A ?= -lz

SYSCALL_INTERFACE_DIR ?= $(dir $(THIS_MAKEFILE))/../../syscall-interfaces/scripts
SYSCALL_INTERFACE := linux

vpath %.c $(SYSCALL_INTERFACE_DIR)
vpath %.c $(LIBALLOCS)/src

CFLAGS += -g 
CFLAGS += -Wall -Wno-unused-label -Wno-comment
CFLAGS += -O2
CFLAGS += -fPIC
CFLAGS += -ffreestanding
CFLAGS += -I$(SYSCALL_INTERFACE_DIR)

CFLAGS += -I $(LIBALLOCS)/include
# CFLAGS += $(LLVM_INCLUDES)

CXXFLAGS := $(CXXFLAGS) $(CFLAGS) # eagerly latch CFLAGS now; don't want later additions
CFLAGS += -std=c99
CXXFLAGS += -std=c++11 $(LLVM_CXXFLAGS)

SYSCALL_IFACE_SRC := $(SYSCALL_INTERFACE)-syscall-ifacetypes.c

C_SRC := $(wildcard *.c) $(SYSCALL_IFACE_SRC) uniqtype-bfs.c
S_SRC := $(wildcard *.s)
CC_SRC := $(wildcard *.cc)

C_DEPS := $(patsubst %.c,.%.d,$(C_SRC))
CC_DEPS := $(patsubst %.cc,.%.d,$(CC_SRC))
DEPS := $(C_DEPS) $(CC_DEPS)
OBJS := $(patsubst %.c,%.o,$(C_SRC)) $(patsubst %.cc,%.o,$(CC_SRC)) $(patsubst %.s,%.o,$(S_SRC))

DEPS += .trap-syscalls-exec.d

$(CC_DEPS): .%.d: %.cc
	$(CXX) -MM $(CXXFLAGS) $+ > "$@" || rm -f "$@"
$(C_DEPS): .%.d: %.c
	$(CC) -MM $(CFLAGS) $+ > "$@" || rm -f "$@"

ifneq ($(MAKECMDGOALS),clean)
-include $(DEPS)
endif

# Don't build via .o, because we need different compile-time flags depending on 
# which target we're building.

trap-syscalls-exec.o: trap-syscalls.c
	$(CC) $(filter-out -fPIC,$(CFLAGS)) -DEXECUTABLE -o "$@" "$<"

# standalone program, for testing
trap-syscalls: $(filter-out trap-syscalls.o,$(OBJS)) trap-syscalls-exec.o
	$(CXX) $(filter-out -fPIC,$(CFLAGS)) -o "$@" $+ $(LDFLAGS) $(LDLIBS)

dynamic-list: $(patsubst %.c,%.o,$(SYSCALL_IFACE_SRC))
	( echo '{'; nm --format=posix "$<" | sed 's/[[:blank:]].*/;/'; echo '};') > "$@" || rm -f "$@"

# disable sbrk() in dlmalloc, to avoid conflicting with the "other" C library
dlmalloc.o: CFLAGS += -O3 -DHAVE_MORECORE=0
# We put dlmalloc in a library so that --exclude-libs=ALL will hide its symbols
# in our output .so, so that they don't override anything in the rest of the program.
dlmalloc.a: dlmalloc.o
	$(AR) r "$@" $^

# We have to defsym __GI____assert_fail because it's defined in the same file as 
# __assert_fail, and some libc symbols refer to it using this alias. Otherwise
# the libc archive's __assert_fail gets pulled in because it's the only definition
# of __GI____assert_fail, and we have to use its __assert_fail too.

# FIXME: make our dynamic symbols hidden! 
# We don't want user code calling into our exit(), hence having us make its syscalls.
trap-syscalls.so: LDLIBS := -Bstatic $(LIBOPDIS_A) $(LIBOPCODES_A) $(LIBBFD_A) $(LIBIBERTY_A) $(ZLIB_A) dlmalloc.a $(LIBC_A)
trap-syscalls.so: LDFLAGS += -nostdlib -Wl,--hash-style=sysv
trap-syscalls.so: $(OBJS) dynamic-list
	$(CC) -shared -Bsymbolic -Wl,--dynamic-list,dynamic-list -Wl,--exclude-libs=ALL -Wl,-h,trap-syscalls.so -Wl,--version-script,version-script -o "$@" $(filter-out dynamic-list,$(filter-out raw-syscalls.o,$+)) $(LDFLAGS) raw-syscalls.o -Wl,--defsym,__GI___assert_fail=__assert_fail $(LDLIBS) 

.PHONY: clean
clean:
	rm -f trap-syscalls trap-syscalls.so
	rm -f *.o
	rm -f .*.d
