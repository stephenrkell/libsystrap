#ifndef CHAIN_H_
#define CHAIN_H_

#include "chain-decls.h"
#include "donald.h"

#if !defined(OUR_LDSO_DIR)
#warning "Using './' as the directory containing the ld.so"
#define OUR_LDSO_DIR "./"
#endif

#define OUR_LDSO_NAME OUR_LDSO_DIR DONALD_NAME ".so"
#endif
