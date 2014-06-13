#ifndef __MALLOC_H__
#define __MALLOC_H__

#include <unistd.h>

void *malloc (size_t size);
void free (void *ptr);
void *calloc (size_t nmemb, size_t size);
void *realloc (void *ptr, size_t size);

#endif // __MALLOC_H__
