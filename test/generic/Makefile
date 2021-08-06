.PHONY: default
default: $(foreach t,hello time truemk-execve truesh-execve,run-$(t)-$(MODE).stamp)

# FIXME: we skip 'read' and 'write' as they exit nonzero even on success

THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))
srcroot := $(realpath $(dir $(realpath $(THIS_MAKEFILE)))/../..)
$(info srcroot is $(srcroot))

include $(srcroot)/test/rules.mk

clean::
	rm -f hello time read write

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
time read write: LDFLAGS += -nostdlib -nostartfiles -ffreestanding

time: LDFLAGS += -no-pie
time: LDLIBS += $(LDSO)

# without this, for some reason 'make' doesn't find the recipe for hello
# ... I guess it has a depth limit on searching for not-yet-existing files
# to instantiate '%' with?
hello: hello.c
truemk-execve: truemk-execve.c
truesh-execve: truesh-execve.c
