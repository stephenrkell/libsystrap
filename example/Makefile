THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))
srcroot := $(realpath $(dir $(THIS_MAKEFILE)))/..

SYS := $(shell uname -s | tr A-Z a-z )

# for debugging
CFLAGS += -save-temps

ARCH ?= $(shell gcc -print-multiarch | sed 's/-.*//' )
ifeq ($(ARCH),i386)
LD_SO ?= /lib/ld-linux.so.2
else
ifeq ($(ARCH),x86_64)
LD_SO ?= /lib64/ld-linux-x86-64.so.2
endif
endif

ifeq ($(LD_SO),)
$(error Could not determine ld.so pathname (from architecture $(ARCH)).)
endif

UNWIND_MACHINE ?= $(ARCH)
ifeq ($(UNWIND_MACHINE),i386)
UNWIND_MACHINE := x86
endif

CONTRIB := $(srcroot)/contrib
CONFIG ?= $(CONTRIB)/config.mk
DONALD ?= $(srcroot)/contrib/donald

default: trace-syscalls.so trace-syscalls-ld.so

$(CONTRIB)/config.mk:
	$(MAKE) -C $(CONTRIB)

ifeq ($(SYS),freebsd)
LIBC_A ?= /usr/lib/libc_pic.a
endif
include $(CONFIG)

CFLAGS += $(LIBC_CFLAGS)
CFLAGS += -DSYSTRAP_DEFINE_FILE

ifeq ($(LIBRUNT_DIR),)
$(error Please install the librunt source tree and set LIBRUNT_DIR to point to it)
endif

ifeq ($(realpath $(srcroot)/lib/libsystrap.a),)
$(error Please build libsystrap first)
endif

CFLAGS += -g 
CFLAGS += -Wall -Wno-unused-label -Wno-comment
ifeq ($(DEBUG),)
CFLAGS += -O2
endif
CFLAGS += -fPIC
CFLAGS += -ffreestanding -fno-omit-frame-pointer
CFLAGS += -I$(srcroot)/include
CFLAGS += -I $(LIBRUNT_DIR)/include
CFLAGS += -std=c99

syscall-names.o: $(SYS)-syscall-macros.h

# for dlmalloc.c
vpath %.c $(srcroot)/contrib

# for donald things
vpath %.c $(DONALD)/src

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
	( /usr/bin/cpp -E -dM -o - /usr/include/`gcc -print-multiarch`/asm/unistd.h </dev/null | \
           grep '#define *__NR_' | sort | uniq | \
           sed -r 's/^#define *__NR_([^[:blank:]]*)[[:blank:]]*([0-9]*)/#ifdef SYS_\1\nSYSCALL(\1, \2)\n#endif/') > "$@" || (rm -f "$@"; false)
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
	$(srcroot)/lib/libsystrap.a \
	-Wl,--whole-archive $(LIBRUNT_DIR)/lib/librunt_preload.a -Wl,--no-whole-archive \
	-ldl

# FIXME: what's the right way to pull in libgcc.a? It seems that
# the compiler should do it for us, but for some reason it doesn't.
trace-syscalls.so: LDLIBS += \
	dlmalloc.a \
	$(LD_SO) \
	$(LIBC_A) -lunwind-$(UNWIND_MACHINE) -lunwind -lpthread -lgcc

# we used to insist -Wl,--hash-style=sysv here, but relf.h now groks GNU-style
trace-syscalls.so: LDFLAGS += \
-fno-lto -nostdlib -Wl,--no-as-needed \
-Wl,--defsym,__private_strdup=strdup -Wl,--defsym,__private_malloc=malloc \
-Wl,--defsym,__private_free=free \
-Wl,--defsym,__wrap___runt_files_notify_load=__runt_files_notify_load \
-Wl,--defsym,__wrap___runt_files_metadata_by_addr=__runt_files_metadata_by_addr
# hmm -- is this necessary now? FIXME: CHECK
trace-syscalls.so: LDFLAGS += \
-Wl,--defsym,stat=raw_stat
# for debugging, output a map file
trace-syscalls.so: LDFLAGS += \
  -Wl,-Map,trace-syscalls.map
# don't use lazy binding -- it's bad if we've removed exec permission
trace-syscalls.so: LDFLAGS += \
	-Wl,-z,now -fno-lto -Wl,--exclude-libs=ALL
# we define our own, simpler __init_tp
trace-syscalls.so: LDFLAGS += -Wl,--wrap,__init_tp
trace-syscalls-ld.so: LDFLAGS += -Wl,--wrap,__init_tp

trace-syscalls.so: trap-syscalls.o syscall-names.o dlmalloc.a

trace-syscalls.so: $(srcroot)/lib/libsystrap.a
	$(CC) -shared -Bstatic -static-libgcc \
		-fuse-ld=gold \
		-Wl,-h,$@ \
		-o "$@" $(filter-out %.a,$+) \
		$(LDFLAGS) $(LDLIBS)

OBJS := premain.o main.o entry.o load.o

$(OBJS): CFLAGS += -DDONALD_NAME=\"trace-syscalls-ld\" \
  -DCHAIN_LOADER
# FIXME: localize all global symbols except maybe _start?
trace-syscalls-ld.so: trace-syscalls-ld.lds $(OBJS)
	$(CC) $(CFLAGS) -fuse-ld=bfd \
            -Bsymbolic -nostdlib -nostartfiles -shared -o "$@" \
            $(filter-out %.lds,$+) \
            -Wl,-Bstatic $(srcroot)/src/libsystrap.a $(LIBC_A) -Wl,-Bsymbolic \
            -T $(filter %.lds,$+) -Wl,-soname=ld-linux.so.2 

trace-syscalls-ld.lds: $(shell which ld) $(THIS_MAKEFILE)
	USE_LD=ld.bfd $(CC) -fuse-ld=bfd -nostdlib -nostartfiles -shared \
      -Wl,--verbose 2>&1 |  \
        LC_ALL=C \
          sed -e '/^=========/,/^=========/!d;/^=========/d'    \
              -e 's/\. = .* + SIZEOF_HEADERS;/& _begin = . - SIZEOF_HEADERS;/' \
              -e 's/\. = DATA_SEGMENT_ALIGN.*/. = DATA_SEGMENT_ALIGN (CONSTANT (COMMONPAGESIZE), CONSTANT (COMMONPAGESIZE));/' \
          > "$@" || (rm -f $@; false)

.PHONY: clean
clean:
	rm -f trace-syscalls.so trace-syscalls-ld.so
	rm -f *.o *.a
	rm -f .*.d
