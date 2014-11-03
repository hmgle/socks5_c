#ifndef _DEBUG_H
#define _DEBUG_H

#include <stdio.h>
#include <stdlib.h>

#ifndef DEBUG
#define debug_print(fmt, ...)
#define DIE(fmt, ...)
#else
#define debug_print(fmt, ...) fprintf(stderr, "DEBUG %s:%d: %s():" fmt "\n", __FILE__, __LINE__, __func__, ##__VA_ARGS__)
#define DIE(fmt, ...) { debug_print(fmt, ##__VA_ARGS__); exit(-1); }
#endif

#endif
