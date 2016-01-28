#!/bin/bash

export LD_PRELOAD=$( dirname "$0" )/../src/trap-syscalls.so

exec "$@"
