#!/usr/bin/env python3

import functools
import os
import os.path
import pdb
import shlex
import subprocess
import sys

from subprocess import STDOUT, PIPE, DEVNULL

SCRIPT_DIR = os.path.dirname(__file__)
TRAP_SYSCALLS_SO = os.path.join(SCRIPT_DIR, '../src/trap-syscalls.so')
SYSCALL_STP = os.path.join(SCRIPT_DIR, 'copy-tofrom-user.stp')
BUFSIZE = 1024

def start_stap(trap_proc, stdin=DEVNULL, stdout=PIPE, stderr=PIPE):
    return subprocess.Popen(shlex.split('stap -v -x {pid} {stp}'.format(pid=trap_proc.pid, stp=SYSCALL_STP)), stdin=stdin, stdout=stdout, stderr=stderr, bufsize=0)

def start_trap(args, stdin=DEVNULL, stdout=PIPE, stderr=PIPE):
    pipe_r, pipe_w = os.pipe()
    env = {
        'LD_PRELOAD': TRAP_SYSCALLS_SO,
        'TRAP_SYSCALLS_SLEEP_FOR_SECONDS': str(15),
        'TRAP_SYSCALLS_FOOTPRINT_FD': str(pipe_w),
        'TRAP_SYSCALLS_FOOTPRINT_SPEC_FILENAME': '/tmp/thing',
        'TRAP_SYSCALLS_DEBUG': str(0),
    }
    print("starting {!r}".format(args))
    trap_proc = subprocess.Popen(args, env=env, stdin=stdin, stdout=stdout, stderr=stderr, pass_fds=[pipe_r, pipe_w], bufsize=0)
    os.close(pipe_w)
    return (trap_proc, pipe_r)

def main(args):
    trap_proc, footprint_fd = start_trap(args)
    stap_proc = start_stap(trap_proc, stderr=STDOUT)
    all_pipes = {
        '/tmp/trap_footprint': os.fdopen(footprint_fd, 'rb'),
        '/tmp/trap_out': trap_proc.stdout,
        '/tmp/trap_err': trap_proc.stderr,
        '/tmp/stap_out': stap_proc.stdout,
        '/tmp/stap_err': stap_proc.stderr,
    }
    files = {name: open(name, 'wb') for name in all_pipes.keys()}
    try:
        while True:
            trap_proc.poll()
            if trap_proc.returncode is not None and stap_proc.returncode is None:
                stap_proc.terminate()
            open_pipes = {name: f for name, f in all_pipes.items() if f is not None and not f.closed}
            if len(open_pipes) < 1:
                break
            for name, f in open_pipes.items():
                buf = f.read(BUFSIZE)
                print('read {} bytes from {!s}, '.format(len(buf), f), end='')
                if len(buf) == 0:
                    f.close()
                    files[name].close()
                    print('closed {}'.format(name))
                else:
                    wrote = files[name].write(buf)
                    print('wrote {} bytes to {}'.format(wrote, name))
                sys.stdout.flush()
    finally:
        for f in list(files.values()) + list(all_pipes.values()):
            try:
                f.close()
            except Exception:
                pass

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
    
    

