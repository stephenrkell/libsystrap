#!/usr/bin/env python2

from __future__ import print_function

import capstone
import pdb
import pprint
import re
import struct
import sys

from capstone.x86_const import *

from pybfd.bfd_archs import *
from pybfd.bfd_base import *

from pybfd.bfd import Bfd
from pybfd.opcodes import Opcodes

WORDSIZE = 64
ARCH = ARCH_I386
MACH = MACH_X86_64
ENDIAN = ENDIAN_MONO
SIZEOF_INT = 4
MAX_EXCEPTION_BYTES = 100

EFAULT_32 = 0xfffffff2
EFAULT_64 = 0xfffffffffffffff2

REG_NAMES = {getattr(capstone.x86_const, k): k.split('_')[2].lower()
                         for k in dir(capstone.x86_const) if k.startswith('X86_REG_')}

REG = r'%(?P<{}>[A-Za-z0-9]+)'
MOV = r'mov[a-z]?\s+'
JMP = r'jmp[a-z]?\s+'
NUM = r'((?P<{0}hex>0x[A-Fa-f0-9]+)|(?P<{0}oct>0[0-9]+)|(?P<{0}dec>[1-9][0-9]*))'
ADDR = NUM.format('disp_') + r'?\(' + REG.format('base_reg') + ',' + REG.format('index_reg') + NUM.format('mult_') + r')?\)'
REP_REGEX = re.compile('')
#READ_REGEX = re.compile(MOV + ADDR + ',' + REG.format('reg'))
#WRITE_REGEX = re.compile(MOV + REG.format('reg') + ',' + ADDR)
EFAULT_REGEX = re.compile(MOV + r'\$0xf+2,' + REG.format('reg'))
JMP_REGEX = re.compile(JMP + NUM.format(''))

def num(match, prefix=''):
    if match.group(prefix + 'hex') is not None:
        return int(match.group(prefix + 'hex'), base=16)
    elif match.group(prefix + 'oct') is not None:
        return int(match.group(prefix + 'oct'), base=8)
    elif match.group(prefix + 'dec') is not None:
        return int(match.group(prefix + 'dec'), base=10)
    else:
        return None

def unsigned(n, bits=WORDSIZE):
    if n < 0:
        return n + 2 ** bits
    else:
        return n

def section_contains(section, addr):
    base = unsigned(section.vma)
    return (addr - base) < (base + section.size)

def table_pairs(table):
    content = table.content
    base = unsigned(table.vma)
    for i in xrange(0, len(content), 2 * SIZEOF_INT):
        key, val = struct.unpack('<ii', content[i:i + 2 * SIZEOF_INT])
        if val - key >= 0x7ffffff0 - 4:
            # special hack for uaccess_err, see linux/arch/x86/mm/extable.c
            # we ignore these because they're only used for signal frame handling
            continue
        key += base + i
        val += base + i + SIZEOF_INT
        yield (key, val)

def suffix_to_length(s):
    if s == 'b':
        return 1
    elif s == 'w':
        return 2
    elif s == 'l':
        return 4
    elif s == 'q':
        return 8
    else:
        return None

def mov_length(i):
    assert len(i.operands) == 2
    assert i.mnemonic.startswith('mov')
    if len(i.mnemonic) in (4, 5, 7):
        return suffix_to_length(i.mnemonic[-1])
    elif len(i.mnemonic) == 6:
        return suffix_to_length(i.mnemonic[-2])
    else:
        assert False

def decode_mov_operand(op, direction):
    if op.type == X86_OP_REG:
        return (['{}=reg:{}'.format(direction, REG_NAMES[op.reg])], [])
    elif op.type == X86_OP_IMM:
        return (['{}=imm:0x{:x}'.format(direction, op.imm)], [])
    elif op.type == X86_OP_MEM:
        register = 'register("{}")'
        segment = '0' if op.mem.segment == X86_REG_INVALID else register.format(REG_NAMES[op.mem.segment])
        base = '0' if op.mem.base == X86_REG_INVALID else register.format(REG_NAMES[op.mem.base])
        index = '0' if op.mem.index == X86_REG_INVALID else register.format(REG_NAMES[op.mem.index])
        return (['{}=mem:%p'.format(direction)],
                 ['({segment} * 16 + {base} + {index} * {scale} + {displacement})'
                           .format(segment=segment, base=base, index=index,
                           scale=op.mem.scale, displacement=op.mem.disp)])
    else:
        assert False


def decode_mov(prev_insn, insn, next_insn):
    assert(len(insn.operands) == 2)
    op1 = insn.operands[0]
    op2 = insn.operands[1]
    op1_formats, op1_args = decode_mov_operand(op1, 'from')
    op2_formats, op2_args = decode_mov_operand(op2, 'to')        
    if insn.mnemonic.startswith('mov'):
        var_decls = []
        other_probes = []
        info_formats = [
            'size={}'.format(mov_length(insn)),
            'addr=0x{:x}'.format(insn.address),
        ]
        info_args = []
    elif insn.mnemonic.startswith('rep mov'):
        var_decls = ['global ecx_at_{:x};'.format(insn.address)]
        other_probes = [' '.join(['probe kprobe.statement(0x{:x}).absolute {{ if (pid() == target()) {{'.format(insn.address),
                                  'ecx_at_{:x} = register("ecx"); }} }}'.format(insn.address)])]
        info_formats = [
            'size=%d',
            'addr=0x{:x}'.format(insn.address),
        ]
        info_args = [
            'ecx_at_{:x}'.format(insn.address)
        ]
        # TODO FIXME
        return ''
    else:
        assert False
    printf_format = info_formats + op1_formats + op2_formats
    printf_args = [''] + info_args + op1_args + op2_args
    printf_statement = 'printf("=== MOV {}\\n"{});'.format(';'.join(printf_format), ', '.join(printf_args))
    printf_probe = ' '.join([('probe kprobe.statement(0x{:x}).absolute {{ if (pid() == target()) {{'
                              .format(next_insn.address)),
                             printf_statement, 'print_backtrace(); print_ubacktrace(); } }'])
    return '\n'.join(var_decls + other_probes + [printf_probe])
        
def print_insn(section, insn):
    insn_bytes = ' '.join('{:02x}'.format(b) for b in insn.bytes)
    print('{section:12} 0x{i.address:016x}: {bytes:42s} {i.mnemonic:10s} {i.op_str}'
          .format(section=section, i=insn, bytes=insn_bytes))
  
def main(args):
    filename = args[1]
    out_filename = args[2]
    bfd = Bfd(filename)
    out_file = open(out_filename, 'w')
    text_section = bfd.sections['.text']
    init_text_section = bfd.sections['.init.text']
    exit_text_section = bfd.sections['.exit.text']
    table_section = bfd.sections['__ex_table']
    ex_table = dict(table_pairs(table_section))
    for k, v in sorted(ex_table.items(), key=lambda i: i[1]):
        print('0x{:016x} => 0x{:016x}'.format(k, v))

    #addr = int(args[2], 16)
    #start = addr - unsigned(text_section.vma)
    opcodes = Opcodes(ARCH, MACH, ENDIAN)
    #print('0x{:016x}'.format(addr))
    print("=== disassembling .text sections of kernel image...", end='')
    sys.stdout.flush()

    

    disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    disassembler.syntax = capstone.CS_OPT_SYNTAX_ATT
    disassembler.detail = True
    disassembler.skipdata = True

    text_disassembly = {i.address: i for i in disassembler.disasm(text_section.content,
                                                                  unsigned(text_section.vma))}
    init_text_disassembly = {i.address: i for i in disassembler.disasm(init_text_section.content,
                                                                       unsigned(init_text_section.vma))}
    exit_text_disassembly = {i.address: i for i in disassembler.disasm(exit_text_section.content,
                                                                       unsigned(exit_text_section.vma))}

    disassemblies = {
        '.text': text_disassembly,
        '.init.text': init_text_disassembly,
        '.exit.text': exit_text_disassembly,             
    }

    print("done.")

    def addr_within_section(addr, name):
        vma = unsigned(bfd.sections[name].vma)
        size = bfd.sections[name].size
        return (vma <= addr < vma + size)

    def find_previous_insn(section, address):
        prev = address - 1
        while prev not in disassemblies[section]:
            prev -= 1
        return prev

    def get_disassembly(addr):
        for name, disassembly in disassemblies.items():
            if addr_within_section(addr, name):
                return name, disassembly[addr]
        # not found
        print("target address outside any known *.text section!")
        assert False

    kprobes = []

    for site, handler in sorted(ex_table.items(), key=lambda i: i[1]):
        print('============================================= considering handler at 0x{:016x} for 0x{:016x}'.format(handler, site))
        current_addr = handler
        err_reg = None
        err_val = None
        print('-------- disassembling site')
        site_section, site_insn = get_disassembly(site)
        print_insn(site_section, site_insn)
        if not (site_insn.mnemonic.startswith('mov') or site_insn.mnemonic.startswith('rep mov')):
            print('site is not a MOV, skipping')
            continue
        elif len(site_insn.operands) != 2:
            assert False, 'MOV without two operands?'
        elif site_insn.operands[0].type != X86_OP_MEM and site_insn.operands[1].type != X86_OP_MEM:
            print('site doesn\'t touch memory, skipping')
            continue

        print('-------- disassembling handler')
        for i in range(10): # max 10 instructions in handler
            handler_section, handler_insn = get_disassembly(current_addr)
            print_insn(handler_section, handler_insn)
            current_addr += handler_insn.size
            if handler_insn.insn_name().startswith('mov'):
                print('found a MOV')
                if handler_insn.prefix[0] not in (0, X86_PREFIX_LOCK) or handler_insn.prefix[1] != 0:
                    print('unknown prefix {!r}'.format(handler_insn.prefix))
                    continue
                assert len(handler_insn.operands) == 2
                op1 = handler_insn.operands[0]
                op2 = handler_insn.operands[1]
                if op1.type == X86_OP_IMM:
                    from_str = 'printf("to=imm:%p", {})'.format(op1.imm)
                    if op2.type == X86_OP_REG:
                        if op1.size == 4 and op1.imm == EFAULT_32:
                            err_reg = REG_NAMES[op2.reg]
                            err_val = EFAULT_32
                            print("found the err_reg ({})".format(err_reg))
                            continue
                        elif op1.size == 8 and op1.imm == EFAULT_64:
                            err_reg = REG_NAMES[op2.reg]
                            err_val = EFAULT_64
                            print("found the err_reg ({})".format(err_reg))
                            continue
            elif handler_insn.insn_name() == 'jmp':
                print('found a JMP')
                assert(len(handler_insn.operands) == 1)
                break
                
        print('-------- disassembling site (+/- 1)')
                
        # find previous instruction
        site_minus = find_previous_insn(site_section, site)
        site_minus_section, site_minus_insn = get_disassembly(site_minus)
        site_plus_section, site_plus_insn = get_disassembly(site + site_insn.size)

        print_insn(site_minus_section, site_minus_insn)
        print_insn(site_section, site_insn)
        print_insn(site_plus_section, site_plus_insn)
        #if err_reg is not None:
        #    err_condition = ' && register("{}") != 0x{:x}'.format(err_reg, err_val)
        #else:
        #    # assume that since we got here we succeeded...?
        #    err_condition = ''
        #    pass
        new_kprobe = decode_mov(site_minus_insn, site_insn, site_plus_insn)
        print(new_kprobe)
        kprobes.append(new_kprobe)

    for kprobe in kprobes:
        print(kprobe)
        out_file.write(kprobe)
        out_file.write('\n')
    out_file.close()
   

if __name__ == '__main__':
    main(sys.argv)
