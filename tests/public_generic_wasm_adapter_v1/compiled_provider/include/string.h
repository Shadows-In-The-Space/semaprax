#ifndef SPX_PG_REFERENCE_STRING_H
#define SPX_PG_REFERENCE_STRING_H
#include <stddef.h>
void *memcpy(void *restrict destination, const void *restrict source, size_t size);
void *memset(void *destination, int byte, size_t size);
int memcmp(const void *left, const void *right, size_t size);
int strcmp(const char *left, const char *right);
size_t strlen(const char *text);
#endif
