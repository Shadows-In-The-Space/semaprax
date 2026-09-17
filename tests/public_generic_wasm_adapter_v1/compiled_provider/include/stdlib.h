#ifndef SPX_PG_REFERENCE_STDLIB_H
#define SPX_PG_REFERENCE_STDLIB_H
#include <stddef.h>
void *malloc(size_t size);
void free(void *pointer);
_Noreturn void abort(void);
#endif
