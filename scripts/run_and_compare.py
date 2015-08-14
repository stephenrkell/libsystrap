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
import pprint

import compare_runs
import run_with_stap

def main(args, spec='/home/jf451/spec.idl', verbose=False):
    tempdir = run_with_stap.main(args, spec=spec)
    actual_footprints = os.path.join(tempdir, 'stap_out')
    allowed_footprints = os.path.join(tempdir, 'trap_footprint')
    if verbose:
        compare_args = ['-v', actual_footprints, allowed_footprints]
    else:
        compare_args = [actual_footprints, allowed_footprints]
    print('*** Analysing...')
    compare_runs.main(compare_args)
    print('tempdir was:', tempdir)

if __name__ == '__main__':
    if sys.argv[1] == '-v':
        verbose = True
        args = sys.argv[2:]
    else:
        verbose = False
        args = sys.argv[1:]
    
    main(args[1:], spec=args[0], verbose=verbose)
