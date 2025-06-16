.PHONY: default
default: $(foreach m,preload chain,$(foreach t,true getpid clone3,$(t) run-$(t)-$(m).stamp))

include $(dir $(realpath $(lastword $(MAKEFILE_LIST))))/../rules.mk

clean::
	rm -f true getpid clone3

CFLAGS += -g

# getpid always exits non-zero, so how do we check it didn't crash?
run-getpid-preload.stamp: getpid
	output=$$( LD_PRELOAD=$(PRELOAD_BINARY) ./getpid; echo $?); test -n "$$output" && touch $@
run-getpid-chain.stamp: getpid
	output=$$( $(CHAIN_BINARY) ./getpid; echo $?); test -n "$$output" && touch $@

# freestanding assembly tests -- these use a non-PIC idiom
true getpid clone3: LDFLAGS += -no-pie -nostartfiles -nostdlib
# HACK: until glibc bug 25486 is fixed, we have to add -lc
true getpid clone3: LDLIBS += /lib64/ld-linux-x86-64.so.2 -Wl,--no-as-needed -lc
