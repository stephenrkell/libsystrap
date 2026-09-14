#ifndef CHAIN_DECLS_H_
#define CHAIN_DECLS_H_

#define DONALD_NAME "trace-syscalls-ld"

#include "donald.h"

#if !defined(OUR_LDSO_DIR)
#warning "Using './' as the directory containing the ld.so"
#define OUR_LDSO_DIR "./"
#endif

void create_fake_vdso(ElfW(auxv_t) *auxv);

#define OUR_LDSO_NAME OUR_LDSO_DIR DONALD_NAME ".so"
#endif
