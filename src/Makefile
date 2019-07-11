THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))
SRCROOT := $(realpath $(dir $(THIS_MAKEFILE)))/..

SYS := $(shell uname -s | tr A-Z a-z )

CONTRIB := $(SRCROOT)/contrib
CONFIG := $(CONTRIB)/config.mk

default: trace-syscalls.so

$(CONTRIB)/config.mk:
	$(MAKE) -C $(CONTRIB)

ifeq ($(SYS),freebsd)
LIBC_DIR ?= /usr/lib
LIBC_A ?= /usr/lib/libc_pic.a
endif
include $(CONFIG)

CFLAGS += -DRELF_DEFINE_STRUCTURES -DSYSTRAP_DEFINE_FILE

ifeq ($(LIBALLOCS),)
$(error Please install the liballocs source tree and set LIBALLOCS to point to it)
endif

# don't insist on libfootprints
# ifeq ($(LIBFOOTPRINTS_DIR),)
# $(error Please install the libfootprints source tree and set LIBFOOTPRINTS_DIR)
# endif

# ditto for syscall-introspect-tools
# ifeq ($(SYSCALL_INTROSPECT_TOOLS_DIR),)
# $(error Please install the syscall-introspect-tools source tree and set SYSCALL_INTROSPECT_TOOLS_DIR)
# endif

ifeq ($(ANTLR3C_DIR),)
$(error Please install the libantlr3c source tree and set ANTLR3C_DIR)
endif

ifeq ($(realpath $(SRCROOT)/libsystrap/libsystrap.a),)
$(error Please build libsystrap first)
endif

# We don't currently use llvm, but once did; if we do again...
# LLVM_CXXFLAGS ?= $(shell llvm-config --cxxflags)
# LIBLLVM_ARCHIVE ?= -lllvm_X86 -lllvm
# LIBSTDCXX_ARCHIVE ?= -lstdc++
# CFLAGS += $(LLVM_INCLUDES)

FOOTPRINTS_A := $(LIBFOOTPRINTS_DIR)/src/.libs/libfootprints.a $(LIBFOOTPRINTS_DIR)/src/.libs/libfootprints_syscalls.a

# PROBLEM: this archive always contains non-PIC code
# (even if we set CFLAGS to always include -fPIC... libtool interferes).
# ANTLR3C_A := $(ANTLR3C_DIR)/.libs/libantlr3c.a
# Instead, build our own libantlr3c.a from the PIC objects.
ANTLR3C_A := libantlr3c_pic.a 

libantlr3c_pic.a: $(wildcard $(ANTLR3C_DIR)/.libs/*.o)
	$(AR) r "$@" $^

vpath %.c $(LIBALLOCS_DIR)/src
vpath %.h

CFLAGS += -g 
CFLAGS += -Wall -Wno-unused-label -Wno-comment
CFLAGS += -O2
#CFLAGS += -O0
CFLAGS += -fPIC
CFLAGS += -ffreestanding -fno-omit-frame-pointer

# HACK: circular referential structure between us and liballocs
CFLAGS += -I $(LIBALLOCS_DIR)/include
CFLAGS += -I $(LIBFOOTPRINTS_DIR)/include
CFLAGS += -I $(DWARFIDL_DIR)/include
CFLAGS += -I $(ANTLR3C_DIR)
CFLAGS += -I $(ANTLR3C_DIR)/include
CFLAGS += -I $(DWARFIDL_DIR)/parser
CFLAGS += -I $(SRCROOT)/libsystrap
CFLAGS += -I $(SYSCALL_INTROSPECT_TOOLS)/scripts

CXXFLAGS := $(CXXFLAGS) $(CFLAGS) # eagerly latch CFLAGS now; don't want later additions

# can now add C-specific options to CFLAGS
CFLAGS += -std=c99
CXXFLAGS += -std=c++11 $(LLVM_CXXFLAGS)

$(SYS)-syscall-ifacetypes.c:

# This is a quick but incomplete way to build 
linux-syscall-macros.h:
	( /usr/bin/cpp -E -D"__SYSCALL(num,decl)=decl" - </dev/null | \
           sed -r '/^(#.*)?$$/ d' | sort | uniq | sed 's/^\(.*\)/SYSCALL(\1)/') > "$@" || (rm -f "$@"; false)

freebsd-syscall-macros.h:
	cat /usr/include/sys/syscall.h | grep 'SYS_[a-z][A-Za-z0-9_]*' | cut -f2 | \
    sed 's/SYS_\(.*\)/SYSCALL(\1)/' > "$@" || (rm -f "$@"; false)

# Avoid building local incomplete .h if we have the complete one at hand.
# This means we don't need a working syscall-introspect-tools to proceed,
# but we'll pick it up if its syscall-macros.h has been built.
vpath %.h $(SYSCALL_INTROSPECT_TOOLS)/scripts

syscall-macros.h: $(SYS)-syscall-macros.h
	cp "$<" "$@"

syscall-names.o: $(SYS)-syscall-macros.h

# HACK: more liballocs dependency -- split off a librefl or librunt to isolate these?
C_SRC := $(wildcard *.c) uniqtype-bfs.c # $(SYSCALL_IFACE_SRC)
S_SRC := $(wildcard *.s)
CC_SRC := $(wildcard *.cc)

C_DEPS := $(patsubst %.c,.%.d,$(C_SRC))
CC_DEPS := $(patsubst %.cc,.%.d,$(CC_SRC))
DEPS := $(C_DEPS) $(CC_DEPS)
OBJS := $(patsubst %.c,%.o,$(C_SRC)) $(patsubst %.cc,%.o,$(CC_SRC)) $(patsubst %.s,%.o,$(S_SRC))

$(CC_DEPS): .%.d: %.cc
	$(CXX) -MG -MM $(CXXFLAGS) $+ > "$@" || rm -f "$@"
$(C_DEPS): .%.d: %.c
	$(CC) -MG -MM $(CFLAGS) $+ > "$@" || rm -f "$@"

ifneq ($(MAKECMDGOALS),clean)
-include $(DEPS)
endif

#dynamic-list: $(SYSCALL_IFACE_O)
#	( echo '{'; nm --format=posix "$<" | sed 's/[[:blank:]].*/;/'; echo '};') > "$@" || rm -f "$@"

# disable sbrk() in dlmalloc, to avoid conflicting with the "other" C library
dlmalloc.o: CFLAGS += -DHAVE_MORECORE=0
#-O3
# We put dlmalloc in a library so that --exclude-libs=dlmalloc.a will hide its symbols
# in our output .so, so that they don't override anything in the rest of the program.
dlmalloc.a: dlmalloc.o
	$(AR) r "$@" $^

null := #
space := $(null) #
comma := ,
# FIXME: make our dynamic symbols hidden! 
# We don't want user code calling into our exit(), hence having us make its syscalls.
trace-syscalls.so: LDLIBS := -Bstatic \
	$(SRCROOT)/libsystrap/libsystrap.a \

ifneq ($(SYS),freebsd)
trace-syscalls.so: LDLIBS += \
	$(ZLIB_A)
endif

trace-syscalls.so: LDLIBS += \
	dlmalloc.a \
	$(LIBC_A) 

trace-sysfoot.so: LDLIBS := -Bstatic \
	$(SRCROOT)/libsystrap/libsystrap.a \
	$(ZLIB_A) \
	dlmalloc.a \
	$(LIBC_A) \
	$(FOOTPRINTS_A) \
	$(DWARFIDL_DIR)/parser/dwarfidlSimpleCLexer.o \
	$(DWARFIDL_DIR)/parser/dwarfidlSimpleCParser.o \
	$(ANTLR3C_A)

trace-syscalls.so trace-sysfoot.so: LDFLAGS += -nostdlib -Wl,--hash-style=sysv -Wl,--no-as-needed

trace-syscalls.so trace-sysfoot.so: trap-syscalls.o syscall-names.o handle-syscall.o dlmalloc.a
trace-sysfoot.so: $(filter-out dlmalloc.o,$(OBJS)) libantlr3c_pic.a

# We have to defsym __GI____assert_fail because it's defined in the same file as 
# __assert_fail, and some libc symbols refer to it using this alias. Otherwise
# the libc archive's __assert_fail gets pulled in because it's the only definition
# of __GI____assert_fail, and we have to use its __assert_fail too.
trace-syscalls.so trace-sysfoot.so: dynamic-list $(SRCROOT)/libsystrap/libsystrap.a
	$(CC) -shared -Bsymbolic \
		-fuse-ld=gold \
		-Wl,--dynamic-list,dynamic-list \
		-Wl,-h,trace-syscalls.so \
		-Wl,--version-script,version-script \
		-o "$@" $(filter-out dynamic-list,$(filter-out %.a,$+)) \
		$(LDFLAGS) -Wl,-z,muldefs \
		-Wl,--defsym,__GI___assert_fail=__assert_fail -Wl,--defsym,stat=raw_stat \
		-Wl,--exclude-libs=dlmalloc.a \
		$(LDLIBS)

.PHONY: clean
clean:
	rm -f trace-syscalls.so
	rm -f *.o *.a
	rm -f .*.d
