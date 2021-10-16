THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))
srcroot := $(realpath $(dir $(THIS_MAKEFILE)))/..

.PHONY: default
default: trace-syscalls.so trace-syscalls-ld.so

SYS := $(shell uname -s | tr A-Z a-z )

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

# How should we get our config?
# If we don't have one in srcroot, use contrib/
ifneq ($(realpath $(srcroot)/config.mk),)
include $(srcroot)/config.mk
else
include $(srcroot)/contrib/config.mk
$(srcroot)/contrib/config.mk:
	$(MAKE) -C $(srcroot)/contrib config.mk
endif

ifneq ($(MAKECMDGOAL),clean)

ifeq ($(LIBRUNT_DIR),)
$(error Please install the librunt source tree and set LIBRUNT_DIR to point to it)
endif
ifeq ($(XED_DIR),)
$(error Please set XED_DIR)
endif
ifeq ($(DONALD),)
$(error Please set DONALD or make $(srcroot)/config.mk do so)
endif
ifeq ($(SYS),freebsd)
LIBC_A ?= /usr/lib/libc_pic.a
endif
ifeq ($(LIBC_A),)
$(error Please set LIBC_A to point to a position-independent libc archive)
endif
ifeq ($(realpath $(srcroot)/lib/libsystrap.a),)
$(error Please build libsystrap first)
endif

endif

CFLAGS += -DOUR_LDSO_DIR="\"$(shell pwd)/\""
CFLAGS += $(LIBC_CFLAGS)
CFLAGS += -DSYSTRAP_DEFINE_FILE
CFLAGS += -DASSERT_FAIL_LINE_SIGNED   # see note in src/Makefile
CFLAGS += -I$(XED_DIR)/include

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
vpath %.h $(DONALD)/src
CFLAGS += -I$(DONALD)/src

C_SRC := $(wildcard *.c)
C_DEPS := $(patsubst %.c,.%.d,$(C_SRC))
DEPS := $(C_DEPS)
LOCAL_OBJS := $(filter-out pre-entry.o,$(filter-out write-footprints.o,$(patsubst %.c,%.o,$(C_SRC))))
$(info LOCAL_OBJS is $(LOCAL_OBJS))

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
           sed -r 's/^#define *__NR_([^[:blank:]]*)[[:blank:]]*([0-9]*)/#ifdef SYS_\1\nSYSCALL(\1)\n#endif/') > "$@" || (rm -f "$@"; false)
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
trace-syscalls.so trace-syscalls-ld.so: LDFLAGS += \
-fno-lto -nostdlib -Wl,--no-as-needed
trace-syscalls.so: LDFLAGS += \
-Wl,--defsym,__private_malloc=malloc \
-Wl,--defsym,__private_free=free \
-Wl,--defsym,__wrap___runt_files_notify_load=__runt_files_notify_load \
-Wl,--defsym,__wrap___runt_files_metadata_by_addr=__runt_files_metadata_by_addr \
-Wl,--defsym,__private_strdup=strdup
# hmm -- is this necessary now? FIXME: CHECK
trace-syscalls.so: LDFLAGS += \
-Wl,--defsym,stat=raw_stat
# don't use lazy binding -- it's bad if we've removed exec permission
trace-syscalls.so trace-syscalls-ld.so: LDFLAGS += \
	-Wl,-z,now
# generate a map file, for debugging
trace-syscalls.so trace-syscalls-ld.so: LDFLAGS += -Wl,-Map,$@.map
# don't re-export symbols from any archives we link in
trace-syscalls.so trace-syscalls-ld.so: LDFLAGS += \
      -Wl,--exclude-libs=ALL

# To avoid clashing implementations of TLS,
# we define our own, simpler __init_tp -- wrapping DOESN'T WORK...
trace-syscalls.so trace-syscalls-ld.so: LDFLAGS += -Wl,--wrap,__init_tp
# ... we can just use musl's for -ld.so, but for preload we need more.
trace-syscalls.so: LDFLAGS += -Wl,-z,muldefs -Wl,--defsym,__init_tp=__wrap___init_tp

# we insert our startup logic by wrapping enter()
trace-syscalls-ld.so: LDFLAGS += -Wl,--wrap,enter -Wl,--wrap,load_one_phdr \
-Wl,--defsym,__wrap___runt_files_notify_load=__runt_files_notify_load \
-Wl,--wrap,__runt_files_metadata_by_addr
trace-syscalls-ld.so: LDLIBS += -Bstatic \
  $(srcroot)/src/libsystrap.a \
  $(LIBRUNT_DIR)/lib/librunt_preload.a \
  $(LIBC_A)

trace-syscalls.so: trace-syscalls.o syscall-names.o dlmalloc.a fake-tls.o

trace-syscalls.so: $(srcroot)/lib/libsystrap.a
	$(CC) -shared -static-libgcc \
		-fuse-ld=gold \
		-Wl,-soname=$@ \
		-o "$@" $(filter-out %.a,$+) \
		$(LDFLAGS) $(LDLIBS)

LDSO_OBJS := premain.o main.o entry.o load.o pre-entry.o
# ask for a spare .dynamic slot
trace-syscalls-ld.so: LDFLAGS += -Wl,--spare-dynamic-tags=5

$(LDSO_OBJS): CFLAGS += -DDONALD_NAME=\"trace-syscalls-ld\" \
  -DCHAIN_LOADER \
  -DCHAIN_LOADER_COVER_TRACKS_DECLS='$(shell cat chain-decls.h)' \
  -DCHAIN_LOADER_COVER_TRACKS='frob_dynamic(base_addr, inferior_dynamic_vaddr, phdrs, ehdr.e_phnum); \
    set_inferior_metadata(&ehdr, shdrs, phdrs, base_addr); \
    create_fake_vdso(p_auxv); '

bootstrap.o: CFLAGS += -DCHAIN_LOADER

# FIXME: localize all global symbols except maybe _start?
trace-syscalls-ld.so: trace-syscalls-ld.lds $(LDSO_OBJS) $(filter-out fake-tls.o,$(LOCAL_OBJS)) dynamic-list
	$(CC) $(CFLAGS) -fuse-ld=bfd \
            -Bsymbolic -nostdlib -nostartfiles -static-libgcc -shared -o "$@" \
            $(filter-out dynamic-list,$(filter-out %.lds,$+)) \
            $(LDFLAGS) $(LDLIBS) -lgcc -Wl,-Bsymbolic \
            -T $(filter %.lds,$+) -Wl,-soname=ld-linux.so.2 \
            -Wl,--dynamic-list,dynamic-list

# There is no way to make _DYNAMIC a dynamic symbol.
# A bit of a HACK, but we look for _init and _fini to find our own load address
# (in find_r_debug()), so try to export them.
dynamic-list:
	printf '{ etext; _init; _fini; };\n' >$@ || (rm -f $@; false)

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
	rm -f syscall-macros.h $(SYS)-syscall-macros.h
