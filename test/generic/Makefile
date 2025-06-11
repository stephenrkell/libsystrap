.PHONY: default
ALLTESTS := hello time truemk-execve truesh-execve sigreturn clone
default: $(foreach t,$(ALLTESTS),run-$(t)-$(MODE).stamp)

# FIXME: we skip 'read' and 'write' as they exit nonzero even on success

THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))
srcroot := $(realpath $(dir $(realpath $(THIS_MAKEFILE)))/../..)
$(info srcroot is $(srcroot))

include $(srcroot)/test/rules.mk

clean::
	rm -f $(ALLTESTS)

# quick hack to get the dynamic linker path
LDSO ?= $(shell ldd /bin/true | grep ld-linux | cut -f2 | sed 's/[[:blank:]].*//')

ifeq ($(MODE),preload)
PREFIX := LD_PRELOAD=$(srcroot)/example/trace-syscalls.so
else
ifeq ($(MODE),chain)
PREFIX := $(srcroot)/example/trace-syscalls-ld.so
endif
endif

CFLAGS += -g -fPIC

# freestanding C tests (not hello)
$(filter-out clone,$(filter-out hello,$(ALLTESTS))): LDFLAGS += -nostdlib -nostartfiles -ffreestanding -no-pie
# while glibc bug 25486 is unresolved, we need to link in libc as well as just the ld.so :-(
$(filter-out hello,$(ALLTESTS)): LDLIBS += $(LDSO) -Wl,--no-as-needed -lc

# without this, for some reason 'make' doesn't find the recipe for hello
# ... I guess it has a depth limit on searching for not-yet-existing files
# to instantiate '%' with?
hello: hello.c
truemk-execve: truemk-execve.c
truesh-execve: truesh-execve.c
sigreturn: sigreturn.c
