#ifndef _DEBUG_H
#define _DEBUG_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#if DEBUG
#define DEBUG_PRINT         1
#else
#define DEBUG_PRINT         0
#endif

#define debug_print(fmt, ...) \
	do { \
		if (DEBUG_PRINT) \
			fprintf(stderr, "debug_print: %s: %d: %s():" \
				fmt "\n", __FILE__, __LINE__, __func__, \
				##__VA_ARGS__); \
	} while (0)

#define DIE(fmt, ...) \
	do { \
		debug_print(fmt, ##__VA_ARGS__); \
		exit(-1); \
	} while (0)

#endif
