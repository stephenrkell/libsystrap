.PHONY: default
default: $(foreach t,true,run-$(t)-$(MODE).stamp)

# we don't use getpid because it exits non-zero even on success
# ... see below

THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))
srcroot := $(realpath $(dir $(realpath $(THIS_MAKEFILE)))/../..)
$(info srcroot is $(srcroot))

include $(srcroot)/test/rules.mk
clean::
	rm -f true getpid

ifeq ($(MODE),preload)
PREFIX := LD_PRELOAD=$(srcroot)/example/trace-syscalls.so
else
ifeq ($(MODE),chain)
PREFIX := $(srcroot)/example/trace-syscalls-ld.so
endif
endif

run-%-$(MODE).stamp: %
	$(PREFIX) ./$* && touch $@

# getpid always exits non-zero, so how do we check it didn't crash?
run-getpid-%.stamp: getpid
	output=$$( $(PREFIX) ./getpid 2>&1); test -z "$$output" && touch $@

# freestanding assembly tests -- these use a non-PIC idiom
true getpid: LDFLAGS += -no-pie -nostartfiles -nostdlib
# HACK: until glibc bug 25486 is fixed, we have to add -lc
true getpid: LDLIBS += /lib64/ld-linux-x86-64.so.2 -Wl,--no-as-needed -lc
