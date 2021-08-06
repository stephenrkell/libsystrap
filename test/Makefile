ARCH ?= $(shell gcc -print-multiarch | sed 's/-.*//' )

# We have various subdirs:
# $(ARCH): arch-specific programs that exercise the tracing example client
# generic: portable programs that exercise the tracing example client
# client: tests that exercise the libsystrap API
# support: tests that sanity-check the supporting libraries (libx86decode, ...)

# Since the tracing example client now has two forms -- preload and chain-load --
# we run the tracing tests against both of those.
# TODO: once the tracer is more mature, we want to cross-check its traces
# against those from strace.

.PHONY: default
default: generic-recursive $(ARCH)-recursive

.PHONY: generic-recursive x86_64-recursive i386-recursive
generic-recursive x86_64-recursive i386-recursive: %-recursive:
	MODE=chain $(MAKE) -C $*
	MODE=preload $(MAKE) -C $*

.PHONY: client-recursive support-recursive
client-recursive:
	$(MAKE) -C client
support-recursive:
	$(MAKE) -C support
