#pragma once

#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>

typedef int8_t   i8;
typedef int16_t  i16;
typedef int32_t  i32;
typedef int64_t  i64;
typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef float    f32;
typedef double   f64;

u32 unix_seconds() {
    struct timeval current_time;
    gettimeofday(&current_time, NULL);
    return current_time.tv_sec;
}

i64 unix_nano() {
    struct timeval current_time;
    gettimeofday(&current_time, NULL);
    return current_time.tv_sec * (i64)1000000 + current_time.tv_usec;
}

int to_hex(const unsigned char *buf, int size, char *dstbuf, int dstbufsize) {
    if (dstbufsize != size * 2 + 1)
        return -1;
    for (int i = 0; i < size; i++)
        sprintf(dstbuf + i*2, "%02x", buf[i]);
    return 0;
}

#define ALLOW  0
#define DENY   1

#define NEWLINES_TO_SPACES(buf)                 \
	for (int i = 0; i < sizeof(buf); i++) {		\
		if (buf[i] == '\n') {					\
			buf[i] = ' ';						\
		}										\
	}

#define TABS_TO_SPACES(buf)						\
	for (int i = 0; i < sizeof(buf); i++) {		\
		if (buf[i] == '\t') {					\
			buf[i] = ' ';						\
		}										\
	}

#define ZEROS_TO_TABS(buf)						\
	for (int i = 0; i < sizeof(buf); i++) {		\
		if (buf[i] == 0) {						\
			if (i > 0 && buf[i - 1] == '\t') {	\
				buf[i - 1] = 0;					\
				break;							\
			} else {							\
				buf[i] = '\t';					\
			}									\
		}										\
	}

#define LOG(args...) fprintf(stdout, ##args);

#define DEBUG(args...) fprintf(stderr, ##args)

#define ASSERT(cond, ...)                       \
    do {                                        \
        if (!(cond)) {                          \
            fprintf(stderr, ##__VA_ARGS__);     \
            exit(1);                            \
        }                                       \
    } while(0)

#define MALLOC(dst, size)                                           \
    do {                                                            \
        dst = malloc(size);                                         \
        ASSERT(dst != NULL, "fatal: failed to allocate memory\n");  \
    } while(0)

#define REALLOC(dst, size)                                              \
    do {                                                                \
        dst = realloc(dst, size);                                       \
        ASSERT(dst != NULL, "fatal: failed to reallocate memory\n");    \
    } while(0)

void ntoa(struct in_addr in, char *buf, int size) {
    ASSERT(size >= 18, "bad size: %d\n", size);
    unsigned char *bytes = (unsigned char *) &in;
    snprintf(buf, 18, "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
}
