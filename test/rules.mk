ifneq ($(MAKECMDGOALS),clean)
ifeq ($(MODE),preload)
file := $(srcroot)/example/trace-syscalls.so
PREFIX := LD_PRELOAD=$(srcroot)/example/trace-syscalls.so
else
ifeq ($(MODE),chain)
file := $(srcroot)/example/trace-syscalls-ld.so
PREFIX := $(file)
else
$(error MODE must be set to either 'chain' or 'preload')
endif
endif
endif

.PHONY: clean
clean::
	rm -f run-*-*.stamp

run-%-$(MODE).stamp: % $(file)
	$(PREFIX) ./$* && touch $@

