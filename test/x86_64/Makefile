.PHONY: default
default: $(foreach t,true getpid clone3,run-$(t)-$(MODE).stamp)
# we don't use getpid because it exits non-zero even on success
# ... see below

THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))
srcroot := $(realpath $(dir $(realpath $(THIS_MAKEFILE)))/../..)
$(info srcroot is $(srcroot))

include $(srcroot)/test/rules.mk
clean::
	rm -f true getpid

ifeq ($(MODE),preload)
PREFIX := LD_PRELOAD=$(srcroot)/build/$(shell uname -m)/trace-syscalls.so
else
ifeq ($(MODE),chain)
PREFIX := $(srcroot)/build/$(shell uname -m)/trace-syscalls-ld.so
endif
endif

CFLAGS += -g

run-%-$(MODE).stamp: %
	$(PREFIX) ./$* && touch $@

# getpid always exits non-zero, so how do we check it didn't crash?
run-getpid-preload.stamp run-getpid-chain.stamp: getpid
	output=$$( $(PREFIX) ./getpid 2>&1); test -n "$$output" && touch $@

# freestanding assembly tests -- these use a non-PIC idiom
true getpid clone3: LDFLAGS += -no-pie -nostartfiles -nostdlib
# HACK: until glibc bug 25486 is fixed, we have to add -lc
true getpid clone3: LDLIBS += /lib64/ld-linux-x86-64.so.2 -Wl,--no-as-needed -lc
