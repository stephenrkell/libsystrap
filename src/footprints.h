#ifndef FOOTPRINTS_H_
#define FOOTPRINTS_H_

void write_footprint(void *base, size_t len, enum footprint_direction direction, const char *syscall);

#endif
