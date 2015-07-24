#!/usr/bin/env python3

import functools
import os
import os.path
import pdb
import shlex
import subprocess
import sys
import re
import pprint
import copy

from subprocess import STDOUT, PIPE, DEVNULL

SCRIPT_DIR = os.path.dirname(__file__)

BACKTRACE_LINE_RE = re.compile(r'^ 0x(?P<addr>[0-9A-Fa-f]+)( : (?P<func>[A-Za-z0-9_]+)\+(?P<func_offset>[^ ]+))?( \[(?P<exe>[^+ ]+)(\+(?P<exe_offset>[^ ]+))?\])?')

SYSCALL_LINE_RE = re.compile(r'^=== syscall (?P<func>[A-Za-z0-9_]+) @ 0x(?P<addr>[0-9A-Fa-f]+) \(0x(?P<arg1>[0-9A-Fa-f]+), 0x(?P<arg2>[0-9A-Fa-f]+), 0x(?P<arg3>[0-9A-Fa-f]+), 0x(?P<arg4>[0-9A-Fa-f]+), 0x(?P<arg5>[0-9A-Fa-f]+), 0x(?P<arg6>[0-9A-Fa-f]+)\)$')
EXTENT_LINE_RE = re.compile(r'^=== extent (?P<func>[A-Za-z0-9_]+) @ 0x(?P<addr>[0-9A-Fa-f]+) to=0x(?P<to>[0-9A-Za-z]+) from=0x(?P<from>[0-9A-Za-z]+) n=0x(?P<n>[0-9A-Za-z]+)$')
EXTENT_ASM_LINE_RE = re.compile(r'^=== extent __(?P<direction>get|put)_user_(?P<n>[0-9]) @ 0x(?P<addr>[0-9A-Fa-f]+) (from|to)=0x(?P<target>[0-9A-Fa-f]+)$')

TRAP_FOOTPRINT_LINE_RE = re.compile(r'^footprint: (?P<direction>read|write|readwrite) base=0x(?P<base>[0-9A-Fa-f]+) n=0x(?P<n>[0-9A-Fa-f]+) syscall=(?P<syscall>[A-Za-z0-9_]+)$')

def indent_str(s, tab='    '):
    return tab + s.replace('\n', '\n' + tab)

@functools.total_ordering
class Hashable:
    def __hash__(self):
        h = 0
        for k in self._hash_attrs:
            v = getattr(self, k)
            if type(v) == list:
                h ^= hash(tuple(v))
            else:
                h ^= hash(v)
        return h

    def __eq__(self, other):
        return hash(self) == hash(other)

    def __lt__(self, other):
        return hash(self) < hash(other)

    def __repr__(self):
        return str(self) #'<{} @0x{:x}: {}>'.format(self.__class__.__name__, id(self), vars(self))

    def __str__(self):
        return '{}:\n{}'.format(self.__class__.__name__, indent_str('\n'.join('{}:\n{}'.format(k, indent_str(pprint.pformat(v))) for k, v in vars(self).items())))

class FootprintExtent(Hashable):
    _hash_attrs = ['func', 'addr', 'from_addr', 'to_addr', 'n', 'backtrace']
    def __init__(self, func=None, addr=None, from_addr=None, to_addr=None, n=None, backtrace=None, syscall=None):
        self.func = func
        self.addr = addr
        self.from_addr = from_addr
        self.to_addr = to_addr
        self.n = n
        self.backtrace = backtrace if backtrace is not None else []
        self.syscall = syscall

class BacktraceEntry(Hashable):
    _hash_attrs = ['addr', 'func', 'func_offset', 'exe', 'exe_offset']
    def __init__(self, addr=None, func=None, func_offset=None, exe=None, exe_offset=None):
        self.addr = addr
        self.func = func
        self.func_offset = func_offset
        self.exe = exe
        self.exe_offset = exe_offset

    def __str__(self):
        return '0x{:x} : {}+{} [{}+{}]'.format(self.addr, self.func, self.func_offset, self.exe, self.exe_offset)

class SyscallInstance(Hashable):
    _hash_attrs = ['syscall', 'args', 'addr', 'extents', 'backtrace', 'extents']
    def __init__(self, syscall=None, args=None, addr=None, extents=None, backtrace=None):
        self.syscall = syscall
        self.args = args
        self.addr = addr
        self.extents = extents if extents is not None else []
        self.backtrace = backtrace if backtrace is not None else []

class FootprintEntry(Hashable):
    _hash_attrs = ['direction', 'base', 'n']
    def __init__(self, direction='readwrite', base=None, n=None, syscall=None, backtrace=None):
        self.direction = direction
        self.base = base
        self.n = n
        self.syscall = syscall
        self.backtrace = backtrace

    def __str__(self):
        return "footprint: {:9s} base=0x{:16x} n=0x{:16x} syscall={:s}".format(self.direction, self.base, self.n, self.syscall)

def parse_backtrace_entry(line):
    m = BACKTRACE_LINE_RE.match(line)
    assert m, line
    args = {
        'addr': int(m.group('addr'), base=16),
        'func': m.group('func'),
        'func_offset': m.group('func_offset'),
        'exe': m.group('exe'),
        'exe_offset': m.group('exe_offset'),
    }
    return BacktraceEntry(**args)
    
        
def parse_backtrace(lines):
    return [parse_backtrace_entry(line) for line in lines]
                
def parse_syscall(line, backtrace):
    m = SYSCALL_LINE_RE.match(line)
    assert m, line
    args = {
        'syscall': m.group('func'),
        'addr': int(m.group('addr'), base=16),
        'backtrace': backtrace,
        'args': [int(x, base=16) for x in [m.group('arg{}'.format(i)) for i in range(1, 7)]]
    }
    return SyscallInstance(**args)

def find_syscall(backtrace):
    for entry in reversed(backtrace):
        if entry.exe == 'kernel' and entry.func is not None and entry.func.startswith('sys_'):
            return entry.func
    return None
    
def parse_extent(line, backtrace):
    m = EXTENT_LINE_RE.match(line)
    if m:
        args = {
            'func': m.group('func'),
            'addr': int(m.group('addr'), base=16),
            'from_addr': int(m.group('from'), base=16),
            'to_addr': int(m.group('to'), base=16),
            'n': int(m.group('n'), base=16),
            'backtrace': backtrace,
            'syscall': find_syscall(backtrace),
        }
        return FootprintExtent(**args)
    else:
        m = EXTENT_ASM_LINE_RE.match(line)
        assert m, line
        direction = m.group('direction')
        n = int(m.group('n'), base=16)
        target = int(m.group('target'), base=16)
        dummy = 0xFFFFFFFFFFFFFFFF
        args = {
            'func': '__{}_user_{}'.format(direction, n),
            'addr': int(m.group('addr'), base=16),
            'from_addr': target if direction == 'get' else dummy,
            'to_addr': target if direction == 'put' else dummy,
            'n': n,
            'backtrace': backtrace,
            'syscall': find_syscall(backtrace),
        }
        return FootprintExtent(**args)
        
def parse_stap(stap):
    lines = stap.split('\n')
    i = -1
    syscalls = set()
    extents = set()
    while i < len(lines) - 1:
        i += 1
        if lines[i].startswith('Pass ') or lines[i].startswith('WARNING'):
            continue
        elif lines[i].startswith('=== '):
            j = i + 1
            while j < len(lines) and len(lines[j].strip()) > 0 and not lines[j].startswith('=== '):
                j += 1
            #print('Parsing backtrace for lines[{}:{}]:'.format(i+1, j))
            #print('\n'.join(lines[i+1:j]))
            backtrace = parse_backtrace(lines[i+1:j])
            if backtrace is not None:
#                if lines[i].startswith('=== syscall '):
#                    syscalls.add(parse_syscall(lines[i], backtrace))
                if lines[i].startswith('=== extent '):
                    extent = parse_extent(lines[i], backtrace)
                    extents.add(extent)
                    syscalls.add(SyscallInstance(extent.syscall))
                else:
                    assert False
            i = j - 1
            continue
        elif len(lines[i].strip()) == 0:
            continue
        else:
            assert False

    syscalls = list(syscalls)
    for extent in extents:
        for syscall in syscalls:
            #if syscall.backtrace == extent.backtrace:
                # print("============================================================ Equal backtraces:")
                # pprint.pprint(syscall.backtrace)
                # pprint.pprint(extent.backtrace)
                # print("============================================================")
            if syscall.syscall == extent.syscall:
                syscall.extents.append(extent)
                break

    

    #return [s for s in syscalls if interesting(s.backtrace) and len(s.extents) > 0]
    return syscalls

def interesting(trace):
    ignore_list = ['pre_handling', 'post_handling', 'write_footprint', 'print_to_streams', '_handle_sigill_debug_printf']
    is_in_trap_syscalls = lambda b: b.exe is not None and b.exe.endswith('trap-syscalls.so')
    has_handle_sigill = any(is_in_trap_syscalls(b) and b.func == 'handle_sigill' for b in trace)
    has_printing_handler = any(is_in_trap_syscalls(b) and b.func in ignore_list for b in trace)
    return (has_handle_sigill and not has_printing_handler)
    
def parse_trap_footprints(trap_str):
    lines = [l for l in trap_str.split('\n') if l.startswith('footprint:')]
    footprints = set()
    for line in lines:
        m = TRAP_FOOTPRINT_LINE_RE.match(line)
        assert m, line
        args = {
            'direction': m.group('direction'),
            'base': int(m.group('base'), base=16),
            'n': int(m.group('n'), base=16),
            'syscall': m.group('syscall')
        }
        footprints.add(FootprintEntry(**args))
    return footprints

def find_matching_base(footprints, target):
    for candidate in footprints:
        if ((candidate.direction == 'readwrite' or target.direction == candidate.direction)
            and target.base >= candidate.base
            and (target.base + target.n) <= (candidate.base + candidate.n)):
            return candidate
    return None

def find_overrunning_base(footprints, target):
    for candidate in footprints:
        if ((candidate.direction == 'readwrite' or target.direction == candidate.direction)
            and target.base >= candidate.base
            and candidate.base <= target.base < (candidate.base + candidate.n)):
            return candidate
    return None

def find_wrong_direction_base(footprints, target):
    for candidate in footprints:
        if ((candidate.direction != 'readwrite' and target.direction != candidate.direction)
            and target.base >= candidate.base
            and (target.base + target.n) <= (candidate.base + candidate.n)):
            return candidate
    return None

def find_overrunning_wrong_direction_base(footprints, target):
    for candidate in footprints:
        if ((candidate.direction != 'readwrite' and target.direction != candidate.direction)
            and target.base >= candidate.base
            and (target.base + target.n) < (candidate.base + candidate.n)):
            return candidate
    return None
    
def compare_footprints(actual, allowed):
    unmatched = 0
    overran = 0
    fine = 0
    wrong_direction = 0
    overran_wrong_direction = 0
    print("=== Allowed footprints:")
    for fp in allowed:
        print(fp)
    print("=======================")
    for fp in actual:
        counterpart = find_matching_base(allowed, fp)
        overran_counterpart = find_overrunning_base(allowed, fp)
        wrong_direction_counterpart = find_wrong_direction_base(allowed, fp)
        overran_wrong_direction_counterpart = find_overrunning_wrong_direction_base(allowed, fp)
        if counterpart is not None:
            print("OK: {} within {}".format(fp, counterpart))
            fine += 1
        elif overran_counterpart is not None:
            print("*** OVERRAN FOOTPRINT: {} overran {}".format(fp, overran_counterpart))
            for b in fp.backtrace:
                print(b)
            overran += 1
        elif wrong_direction_counterpart is not None:
            print("*** WRONG DIRECTION FOOTPRINT: {}".format(fp))
            for b in fp.backtrace:
                print(b)
            wrong_direction += 1
        elif overran_wrong_direction_counterpart is not None:
            print("*** OVERRAN WRONG DIRECTION FOOTPRINT: {} overran {}".format(fp, overran_wrong_direction_counterpart))
            for b in fp.backtrace:
                print(b)
            overran_wrong_direction += 1
        else:
            print("*** UNMATCHED FOOTPRINT: {}".format(fp))
            for b in fp.backtrace:
                print(b)
            unmatched += 1
    if unmatched == 0 and overran == 0:
        print("All OK! ", end='')
    else:
        print("ERRORS. ", end='')

    print('{} fine, {} unmatched, {} overran, {} wrong direction, {} wrong direction overran'.format(fine, unmatched, overran, wrong_direction, overran_wrong_direction))
                
    
def main(args):
    if args[0] == '-v':
        prog_args = args[1:]
        verbose = True
    else:
        prog_args = args[0:]
        verbose = False
    stap_str = open(prog_args[0]).read()
    trap_str = open(prog_args[1]).read()
    syscalls = parse_stap(stap_str)

    actual_footprints = set()
    allowed_footprints = parse_trap_footprints(trap_str)
    
    for syscall in syscalls:
        for extent in syscall.extents:
            if not interesting(extent.backtrace):
                continue
            if verbose:
                print(extent)
            addr = min(extent.to_addr, extent.from_addr)
            direction = "read" if extent.from_addr < extent.to_addr else "write"
            actual_footprints.add(FootprintEntry(direction, addr, extent.n, syscall.syscall, extent.backtrace))
            
    compare_footprints(actual_footprints, allowed_footprints)
                
    

if __name__ == '__main__':
    main(sys.argv[1:])
    
    

