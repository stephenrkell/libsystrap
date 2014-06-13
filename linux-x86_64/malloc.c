#include <stdint.h>

#include "malloc.h"

#define INT_SIZE 64
#define BUCKET_SIZE 4096

static struct {
        uint8_t buckets [INT_SIZE][BUCKET_SIZE];
        uint64_t a_list;
} memory = { 0 };

static void *allocate_first_free_bucket (int b) {
        if (b == INT_SIZE) {
                return 0;
        } else if (!(memory.a_list & 1 << b)) {
                memory.a_list |= 1 << b;
                return (void *) memory.buckets[b];
        } else {
                return allocate_first_free_bucket (++b);
        }
}

void *malloc (size_t size)
{
        if (size == 0) {
                return NULL;
        } else if (size < 0 || size > BUCKET_SIZE ) {
                return (void *) NULL;
        } else {
                return allocate_first_free_bucket(0);
        }
}

/*
 * This really, really should not be called on a pointer that was not created
 * by malloc, calloc or realloc. Really. Don't do it.
 */
void free (void *ptr)
{
        if (!ptr) {
                return;
        }

        int nbucket = ((int) (ptr - (void *) memory.buckets)) / BUCKET_SIZE;

        memory.a_list &= ~(1 << nbucket);
}

/*
 * That's an easy one.
 */
void *calloc (size_t nmemb, size_t size)
{
        return malloc(nmemb * size);
}

/*
 * Who uses realloc anyway?
 */
void *realloc (void *ptr, size_t size)
{
        if (ptr == NULL) {
                return malloc(size);
        } else {
                return ptr;
        }
}
