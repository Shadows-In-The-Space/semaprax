#ifndef SPX_PG_REFERENCE_STDIO_H
#define SPX_PG_REFERENCE_STDIO_H
#include <stddef.h>
typedef int FILE;
#define stderr ((FILE *)1)
#define stdout ((FILE *)2)
int printf(const char *format, ...);
int fprintf(FILE *stream, const char *format, ...);
int snprintf(char *buffer, size_t capacity, const char *format, ...);
int puts(const char *text);
#endif
