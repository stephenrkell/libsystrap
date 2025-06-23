# Since our tests are supposed to be generic, we may want to run them
# for multiple architectures, e.g. both x86_64 and i386.
# So we operate in a per-arch dir and vpath our sources to ..

dirname := $(notdir $(realpath .))
$(info dirname is $(dirname))
ifeq ($(dirname),generic)
ifeq ($(MAKECMDGOALS),)
GOALS := default
endif
.PHONY: $(GOALS)
$(GOALS):
	for arch in `m=$$(uname -m); case "$$m" in (x86_64) echo x86_64 i386 ;; (*) echo "$$m" ;; esac`; do \
             mkdir -p $${arch} && \
             $(MAKE) -C $${arch} -f ../Makefile $(GOALS); \
        done
else
ARCH := $(dirname)
arch := $(dirname)

ifeq ($(ARCH),)
$(error Logic error: could not set ARCH)
endif
vpath %.c ..

ifeq ($(ARCH),i386)
ifeq ($(shell uname -m),x86_64)
CFLAGS += -m32
ASFLAGS += -m32
LDFLAGS +=  -Wl,-melf_i386
endif
endif

ALLTESTS := hello time truemk-execve truesh-execve sigreturn clone
.PHONY: default
default: $(foreach m,preload chain,$(foreach t,$(ALLTESTS),$(t) run-$(t)-$(m).stamp))
# FIXME: we skip 'read' and 'write' as they exit nonzero even on success

include ../../rules.mk

clean::
	rm -f $(ALLTESTS)

CFLAGS += -g -fPIC

# freestanding C tests (not hello)
$(filter-out clone,$(filter-out hello,$(ALLTESTS))): LDFLAGS += -nostdlib -nostartfiles -ffreestanding -no-pie
# while glibc bug 25486 is unresolved, we need to link in libc as well as just the ld.so :-(
$(filter-out hello,$(ALLTESTS)): LDLIBS += $(LDSO) -Wl,--no-as-needed -lc

time sigreturn: CFLAGS += -nostdinc $(LIBC_CFLAGS) -I../../../include
time sigreturn: ../../../build/$(ARCH)/libsystrap.a

run-truemk-execve-preload.stamp run-truemk-execve-chain.stamp: truemk
truemk: ../truemk
	ln -s "$<" "$@"
run-truesh-execve-preload.stamp run-truesh-execve-chain.stamp: truesh
truesh: ../truesh
	ln -s "$<" "$@"

run-time-preload.stamp: time
	LD_PRELOAD=$(PRELOAD_BINARY) ./time; test $$? -lt 128 && touch $@
run-time-chain.stamp: time
	$(CHAIN_BINARY) ./time; test $$? -lt 128 && touch $@

endif
