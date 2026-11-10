#ifndef CHAIN_EXT_H_
#define CHAIN_EXT_H_

#define DONALD_NAME "trace-syscalls-ld"

#include "donald.h"

#if !defined(OUR_LDSO_DIR)
#warning "Using './' as the directory containing the ld.so"
#define OUR_LDSO_DIR "./"
#endif

#define OUR_LDSO_NAME OUR_LDSO_DIR DONALD_NAME ".so"

/* This is a pointer to the link map that the inferior ld.so has created for
 * *us*, under wraparound loading. */
extern struct link_map *wraparound_link_map;
extern const char *our_loader_path;
extern const char *our_absolute_loader_path;
extern const char *our_canonical_loader_path;

#endif
