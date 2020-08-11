THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))
srcroot := $(realpath $(dir $(THIS_MAKEFILE)))/..

SYS := $(shell uname -s | tr A-Z a-z )

LD_SO ?= /lib64/ld-linux-x86-64.so.2  # HACK: sysdep

CONTRIB := $(srcroot)/contrib
CONFIG ?= $(CONTRIB)/config.mk

default: trace-syscalls.so

$(CONTRIB)/config.mk:
	$(MAKE) -C $(CONTRIB)

ifeq ($(SYS),freebsd)
LIBC_A ?= /usr/lib/libc_pic.a
endif
include $(CONFIG)

CFLAGS += -DSYSTRAP_DEFINE_FILE

ifeq ($(LIBRUNT_DIR),)
$(error Please install the librunt source tree and set LIBRUNT_DIR to point to it)
endif

ifeq ($(realpath $(srcroot)/src/libsystrap.a),)
$(error Please build libsystrap first)
endif

CFLAGS += -g 
CFLAGS += -Wall -Wno-unused-label -Wno-comment
CFLAGS += -O2
CFLAGS += -fPIC
CFLAGS += -ffreestanding -fno-omit-frame-pointer
CFLAGS += -I$(srcroot)/include
CFLAGS += -I $(LIBRUNT_DIR)/include
CFLAGS += -std=c99

syscall-names.o: $(SYS)-syscall-macros.h

# for dlmalloc.c
vpath %.c $(srcroot)/contrib

C_SRC := $(wildcard *.c)
C_DEPS := $(patsubst %.c,.%.d,$(C_SRC))
DEPS := $(C_DEPS)
OBJS := $(patsubst %.c,%.o,$(C_SRC))

$(DEPS): .%.d: %.c
	$(CC) -MG -MM $(CFLAGS) $+ > "$@" || rm -f "$@"

ifneq ($(MAKECMDGOALS),clean)
-include $(DEPS)
endif

# disable sbrk() in dlmalloc, to avoid conflicting with the "other" C library
dlmalloc.o: CFLAGS += -DHAVE_MORECORE=0
# We put dlmalloc in a library so that --exclude-libs=dlmalloc.a will hide its symbols
# in our output .so, so that they don't override anything in the rest of the program.
dlmalloc.a: dlmalloc.o
	$(AR) r "$@" $^

# This is a quick but incomplete way to build a number->name mapping
linux-syscall-macros.h:
	( /usr/bin/cpp -E -D"__SYSCALL(num,decl)=decl" -o - /usr/include/asm-generic/unistd.h </dev/null | \
           sed -r '/^(#.*)?$$/ d' | sort | uniq | sed -r 's/^(sys_)?(.*)/#ifdef SYS_\2\nSYSCALL(\2)\n#endif/') > "$@" || (rm -f "$@"; false)
freebsd-syscall-macros.h:
	cat /usr/include/sys/syscall.h | grep 'SYS_[a-z][A-Za-z0-9_]*' | cut -f2 | \
    sed 's/SYS_\(.*\)/SYSCALL(\1)/' > "$@" || (rm -f "$@"; false)
syscall-macros.h: $(SYS)-syscall-macros.h
	cp "$<" "$@"

# FIXME: make our dynamic symbols hidden! 
# We don't want user code calling into our exit(), hence having us make its syscalls.
# NOTE: the --whole-archive is only necessary for debugging, to ensure that
# functions we might want to call from the debugger are actually linked in
trace-syscalls.so: LDLIBS := -Bstatic \
	$(srcroot)/src/libsystrap.a \
	-Wl,--whole-archive $(LIBRUNT_DIR)/lib/librunt_preload.a -Wl,--no-whole-archive

trace-syscalls.so: LDLIBS += \
	dlmalloc.a \
	$(LD_SO) \
	$(LIBC_A) -lunwind-x86_64 -lunwind -lgcc_s -lpthread

# we used to insist -Wl,--hash-style=sysv here, but relf.h now groks GNU-style
trace-syscalls.so: LDFLAGS += \
-fno-lto -nostdlib -Wl,--no-as-needed \
-Wl,--defsym,__private_strdup=strdup -Wl,--defsym,__private_malloc=malloc \
-Wl,--defsym,__private_free=free
# hmm -- is this necessary now? FIXME: CHECK
trace-syscalls.so: LDFLAGS += \
-Wl,--defsym,stat=raw_stat
# for debugging, output a map file
trace-syscalls.so: LDFLAGS += \
  -Wl,-Map,trace-syscalls.map
# don't use lazy binding -- it's bad if we've removed exec permission
trace-syscalls.so: LDFLAGS += \
	-Wl,-z,now -fno-lto -Wl,--exclude-libs=ALL

trace-syscalls.so: trap-syscalls.o syscall-names.o dlmalloc.a

trace-syscalls.so: $(srcroot)/src/libsystrap.a
	$(CC) -shared -Bsymbolic \
		-fuse-ld=gold \
		-Wl,-h,$@ \
		-o "$@" $(filter-out %.a,$+) \
		$(LDFLAGS) $(LDLIBS)

.PHONY: clean
clean:
	rm -f trace-syscalls.so
	rm -f *.o *.a
	rm -f .*.d
