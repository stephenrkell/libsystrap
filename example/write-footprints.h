#ifndef WRITE_FOOTPRINTS_H_
#define WRITE_FOOTPRINTS_H_

extern _Bool __write_footprints;
extern _Bool __write_traces;
extern void *footprints_out; /* really a FILE* */
extern void *traces_out; /* really a FILE* */
extern struct footprint_node *footprints;
extern struct env_node *footprints_env;

void write_footprint(void *base, size_t len, enum footprint_direction direction, const char *syscall);

#endif
