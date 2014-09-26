# Syscall-dsl library

This module deals with generating the semantics of the kernel syscalls.

The Haskell code requires GHC and the Parsec library. One should install
the following packages:

    - ghc
    - libghc-parsec3-dev

and one needs

 sudo cl-asuser apt-get install indent



Here we're trying to build descriptions of the arguments and memory
footprint of the system calls described in that data, as OCaml
definitions wrt the types defined in

  dsl.ml

The

  examples.ml

are some hand-written examples of how things ought to look. 

The automation is in

  headers    
  structs

These directories both contain haskell code that parses some data
(respectively syscalls.h (copied from somewhere in linux) and structs.h (manually pasted from sundry source code and man pages)) and generate

  headers.ml
  structs.ml

in the respective directories.  The intention was to generate C code
from these that does the right copying, but that generation hasn't yet
been started.


The 

  hand-corrections

is some textual description of how things need to be fixed up, but
those are not incorporated into the headers.ml and structs.ml



