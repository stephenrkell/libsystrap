#!/bin/bash

export LD_PRELOAD=$( dirname "$0" )/../src/trap-syscalls.so
export TRAP_SYSCALLS_DEBUG=1
export TRAP_SYSCALLS_FOOTPRINT_FD=7

exec "$@"
