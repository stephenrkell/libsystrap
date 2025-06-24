# Since our tests are supposed to be generic, we may want to run them
# for multiple architectures, e.g. both x86_64 and i386.
# So we provide a way to operate in a per-arch dir and vpath our sources to ..

dirname := $(notdir $(realpath .))
$(info dirname is $(dirname))
ifeq ($(dirname),generic)
# if we're run from 'generic', it might mean we want to run multiple
# arches' tests in their own subdir... if we don't have ARCH

ifeq ($(ARCH),)
# no arch... set a default goal and use per-arch subdirs to do anything

ifeq ($(MAKECMDGOALS),)
# no goals? no problem
GOALS := default
endif
# whatever your goals, we can make them
.PHONY: $(GOALS)
$(GOALS):
	for arch in `m=$$(uname -m); case "$$m" in (x86_64) echo x86_64 i386 ;; (*) echo "$$m" ;; esac`; do \
             mkdir -p $${arch} && \
             $(MAKE) -C $${arch} -f ../Makefile $(GOALS); \
        done
else
# yes-arch 'generic' dir case
# we can run in-place
srcroot := ../..
endif # arch is empty

# what next? we run our tests in-place, i.e. test rules follow endif

else # ... our dirname is *not* generic
# if run from another directory, assume it names the architecture
# and is under

# our dirname is *not* 'generic'
ARCH ?= $(dirname)
srcroot := ../../..
endif

# unless we are the default-goal-defining case (subdirs only), do some tests
ifneq ($(dirname)$(ARCH)$(MAKECMDGOALS),generic)

arch := $(ARCH)
ifeq ($(arch),)
$(error Logic error: could not set ARCH)
endif

vpath %.c ..

ifeq ($(arch),i386)
ifeq ($(shell uname -m),x86_64)
CFLAGS += -m32
ASFLAGS += -m32
LDFLAGS +=  -Wl,-melf_i386
endif
endif

ALLTESTS := hello time truemk-execve truesh-execve sigreturn clone #read write
.PHONY: default
default: $(foreach m,preload chain,$(foreach t,$(ALLTESTS),$(t) run-$(t)-$(m).stamp))

include $(srcroot)/test/rules.mk

clean::
	rm -f $(ALLTESTS)

CFLAGS += -g -fPIC

# freestanding C tests (not hello or clone)
$(filter-out clone,$(filter-out hello,$(ALLTESTS))): \
LDFLAGS += -nostdlib -nostartfiles -ffreestanding -no-pie
# while glibc bug 25486 is unresolved, we need to link in libc as well as just the ld.so :-(
$(filter-out hello,$(ALLTESTS)): LDLIBS += $(LDSO) -Wl,--no-as-needed -lc

time sigreturn: CFLAGS += -nostdinc $(LIBC_CFLAGS) -I$(srcroot)/include
time sigreturn: $(srcroot)/build/$(arch)/libsystrap.a

run-truemk-execve-preload.stamp run-truemk-execve-chain.stamp: truemk
run-truesh-execve-preload.stamp run-truesh-execve-chain.stamp: truesh
truemk: $(srcroot)/test/generic/truemk
	ln -s "$<" "$@" || true
truesh: $(srcroot)/test/generic/truesh
	ln -s "$<" "$@" || true

run-time-preload.stamp: time
	LD_PRELOAD=$(PRELOAD_BINARY) ./time; test $$? -lt 128 && touch $@
run-time-chain.stamp: time
	$(CHAIN_BINARY) ./time; test $$? -lt 128 && touch $@

endif # ifneq just-generic
