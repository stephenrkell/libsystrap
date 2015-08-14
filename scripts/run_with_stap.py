#!/usr/bin/env python3

from __future__ import print_function

import functools
import os
import os.path
import pdb
import shlex
import subprocess
import sys
import re
import tempfile
import shutil
import select
import errno
import signal

from subprocess import STDOUT, PIPE, DEVNULL

SCRIPT_DIR = os.path.dirname(__file__)
TRAP_SYSCALLS_SO = os.path.join(SCRIPT_DIR, '../src/trap-syscalls.so')
SYSCALL_STP = os.path.join(SCRIPT_DIR, 'my_stp.stp')
BUFSIZE = 16 * 1024 * 1024

LDD_RE = re.compile(r'^\s+(?P<unresolved>[^=> ]+?)( => (?P<resolved>[^=> ]+?))? \(0x[0-9a-fA-F]+\)$')

def start_stap(trap_proc, args, tempdir, stdin=DEVNULL, stdout=PIPE, stderr=PIPE):
    raw_library_deps = subprocess.Popen(["/usr/bin/ldd", args[0]], stdout=PIPE).communicate()[0].decode('utf-8').split('\n')
    try:
        os.mkdir(os.path.join(tempdir, 'systemtap_cache'))
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise
    library_deps = []
    for line in raw_library_deps:
        m = LDD_RE.match(line)
        if m:
            if m.group('resolved'):
                library_deps.append(m.group('resolved'))
            elif m.group('unresolved'):
                library_deps.append(m.group('unresolved'))
            else:
                assert False
    library_dep_options = ' '.join('-d "{}"'.format(dep) for dep in library_deps)
    cmd = 'stap -s 1000 -g -DMAXBACKTRACE=100 -DMAXSTRINGLEN=2048 -DTRYLOCKDELAY=1000 -DKRETACTIVE=1000 -DMAXTRYLOCK=10000 -DMAXACTION=10000 -DMAXERRORS=0 -DMAXSKIPPED=1000 -DDEBUG_UPROBES=1 -DINTERRUPTIBLE=0 -DMINSTACKSPACE=1024 -DSTP_NO_OVERLOAD -DSTAP_SUPPRESS_TIME_LIMITS_ENABLE -DMAXNESTING=5 -d kernel --all-modules -d {target} -d {TRAP_SYSCALLS_SO} {library_dep_options} -v -x {pid} {stp}'.format(pid=trap_proc.pid, stp=SYSCALL_STP,library_dep_options=library_dep_options, TRAP_SYSCALLS_SO=TRAP_SYSCALLS_SO, target=args[0])
    print(cmd)
    return subprocess.Popen(shlex.split(cmd), stdin=stdin, stdout=stdout, stderr=stderr, bufsize=0, env={'SYSTEMTAP_DIR': os.path.join(tempdir, 'systemtap_cache')})

def start_trap(args, tempdir, spec='/home/jf451/spec.idl', stdin=DEVNULL, stdout=PIPE, stderr=PIPE):
    pipe_r, pipe_w = os.pipe()
    env = {
        'LD_PRELOAD': TRAP_SYSCALLS_SO,
        'TRAP_SYSCALLS_STOP_SELF': str(1),
        'TRAP_SYSCALLS_SLEEP_FOR_SECONDS': str(1),
        'TRAP_SYSCALLS_FOOTPRINT_FD': str(pipe_w),
        'TRAP_SYSCALLS_FOOTPRINT_SPEC_FILENAME': spec,
        'TRAP_SYSCALLS_DEBUG': str(0),
    }
    env_str = ' '.join('{}="{}"'.format(k, v) for k, v in env.items())
    print("starting {!s} {!s}".format(env_str, ' '.join(args)))
    trap_proc = subprocess.Popen(args, env=env, stdin=stdin, stdout=stdout, stderr=stderr, pass_fds=[pipe_r, pipe_w], bufsize=0)
    #trap_proc = subprocess.Popen(['strace'] + ['-E {}={}'.format(k, v) for k, v in env.items()] + args, stdin=stdin, stdout=stdout, stderr=stderr, pass_fds=[pipe_r, pipe_w], bufsize=0)
    os.close(pipe_w)
    return (trap_proc, pipe_r)


class PipeWrapper:
    def __init__(self, filename, pipe):
        self.filename = filename
        self.pipe = pipe

    def fileno(self):
        return self.pipe.fileno()

    
def main(args, spec='/home/jf451/spec.idl'):
    tempdir = '/tmp' #tempfile.mkdtemp(prefix='run_with_stap_')
    assert len(args) > 0, 'Please provide a target.'
    assert args[0].startswith('/'), 'Please use absolute path to target.'
    trap_proc, footprint_fd = start_trap(args, spec=spec, tempdir=tempdir)
    stap_proc = start_stap(trap_proc, args, tempdir=tempdir)
    all_pipes = {
        os.path.join(tempdir, 'trap_footprint'): os.fdopen(footprint_fd, 'rb'),
        os.path.join(tempdir, 'trap_out'): trap_proc.stdout,
        os.path.join(tempdir, 'trap_err'): trap_proc.stderr,
        os.path.join(tempdir, 'stap_out'): stap_proc.stdout,
        os.path.join(tempdir, 'stap_err'): stap_proc.stderr,
    }
    files = {name: open(name, 'wb') for name in all_pipes.keys()}
    try:
        stap_err_waiting = True
        stap_err_buf = ''
        print('Waiting for systemtap to be ready...')
        while True:
            trap_proc.poll()
            if trap_proc.returncode is not None and stap_proc.returncode is None:
                stap_proc.terminate()
            open_pipes = {name: f for name, f in all_pipes.items() if f is not None and not f.closed}
            if len(open_pipes) < 1:
                break
            ready_pipes = select.select([PipeWrapper(name, f) for name, f in open_pipes.items()], [], [])
            for wrapper in ready_pipes[0]:
                name, f = wrapper.filename, wrapper.pipe
                buf = os.read(f.fileno(), BUFSIZE)
                print('read {} bytes from {!s}, '.format(len(buf), f), end='')
                if len(buf) == 0:
                    f.close()
                    files[name].close()
                    print('closed {}'.format(name))
                else:
                    wrote = files[name].write(buf)
                    files[name].flush()
                    print('wrote {} bytes to {}'.format(wrote, name))
                    if stap_err_waiting and f == stap_proc.stderr:
                        stap_err_buf = stap_err_buf + buf.decode('iso-8859-1')
                        stap_err_lines = stap_err_buf.split('\n')
                        if any('Pass 5: starting run.' in l for l in stap_err_lines):
                            print('...systemtap is ready, resuming tapped process (pid {})'.format(trap_proc.pid))
                            os.kill(trap_proc.pid, signal.SIGCONT)
                            stap_err_waiting = False
                        # if we haven't triggered on a full line by now, forget it
                        stap_err_buf = ''.join(stap_err_buf.split('\n')[-1:])
                sys.stdout.flush()
    finally:
        for f in list(files.values()) + list(all_pipes.values()):
            try:
                f.close()
            except Exception:
                pass
    return tempdir

if __name__ == '__main__':
    print(main(sys.argv[1:]))
    
    

