#ifndef _DEBUG_H
#define _DEBUG_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

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
		debug_print(fmt); \
		exit(-1); \
	} while (0)

#define DEBUG_LOG 1
#if DEBUG_LOG
FILE *DEBUG_LOG_FILE;
char DEBUG_STRING[1024];
#else
FILE *DEBUG_LOG_FILE;
char *DEBUG_STRING;
#endif

#define open_debug_log(filename) do { \
    if (DEBUG_LOG) { \
        DEBUG_LOG_FILE = fopen(filename, "w"); \
    } \
} while (0)

#define debug_log(fmt, ...) do { \
    if (DEBUG_LOG) { \
        snprintf(DEBUG_STRING, 1023, "%s: %s(): %d: " fmt "\n", __FILE__, __func__, __LINE__, ##__VA_ARGS__); \
        fwrite(DEBUG_STRING, 1, strlen(DEBUG_STRING), DEBUG_LOG_FILE); \
        fflush(DEBUG_LOG_FILE); \
    } \
} while (0)

#define close_debug_log() do { \
    if (DEBUG_LOG) { \
        fclose(DEBUG_LOG_FILE); \
    } \
} while (0)

#endif
