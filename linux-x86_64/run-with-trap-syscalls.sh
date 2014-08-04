#!/bin/bash

export LD_PRELOAD=$( dirname "$0" )/trap-syscalls.so

exec "$@"
