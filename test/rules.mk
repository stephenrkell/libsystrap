ifeq ($(MODE),preload)
PREFIX := LD_PRELOAD=$(srcroot)/example/trace-syscalls.so
else
ifeq ($(MODE),chain)
PREFIX := $(srcroot)/example/trace-syscalls-ld.so
else
$(error MODE must be set to either 'chain' or 'preload')
endif
endif

run-%-$(MODE).stamp: %
	$(PREFIX) ./$* && touch $@

