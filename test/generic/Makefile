ALLTESTS := hello time truemk-execve truesh-execve sigreturn clone
.PHONY: default
default: $(foreach m,preload chain,$(foreach t,$(ALLTESTS),$(t) run-$(t)-$(m).stamp))
# FIXME: we skip 'read' and 'write' as they exit nonzero even on success

include ../rules.mk

clean::
	rm -f $(ALLTESTS)

CFLAGS += -g -fPIC

# freestanding C tests (not hello)
$(filter-out clone,$(filter-out hello,$(ALLTESTS))): LDFLAGS += -nostdlib -nostartfiles -ffreestanding -no-pie
# while glibc bug 25486 is unresolved, we need to link in libc as well as just the ld.so :-(
$(filter-out hello,$(ALLTESTS)): LDLIBS += $(LDSO) -Wl,--no-as-needed -lc

sigreturn: ../../build/$(shell uname -m)/libsystrap.a
