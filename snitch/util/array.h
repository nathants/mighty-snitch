#pragma once

#include "util.h"

#define ARRAY_EXPAND_CAPACITY 1024 * 512

#define ARRAY_INIT(array, type)                             \
    u64 array##_size = 0;                                   \
    u64 array##_capacity = ARRAY_EXPAND_CAPACITY;           \
    type *array;											\
	MALLOC(array, sizeof(type) * array##_capacity);

#define ARRAY_ADD(array, size, type)                            \
    do {                                                        \
        if (array##_size + size > array##_capacity) {           \
            array##_capacity += ARRAY_EXPAND_CAPACITY;          \
            REALLOC(array, sizeof(type) * array##_capacity);    \
        }                                                       \
        array##_size += size;                                   \
    } while(0)

#define ARRAY_APPEND(array, val, type)                          \
    do {                                                        \
        if (array##_size == array##_capacity) {                 \
            array##_capacity += ARRAY_EXPAND_CAPACITY;          \
            REALLOC(array, sizeof(type) * array##_capacity);    \
        }                                                       \
        array[array##_size++] = val;                            \
    } while(0)

#define ARRAY_POP(array, dst)                   \
    do {                                        \
        if (array##_size) {                     \
            dst = array[--array##_size];        \
        } else {                                \
            dst = NULL;                         \
        }                                       \
    } while(0)

#define ARRAY_RESET(array)                      \
    do {                                        \
        array##_size = 0;                       \
    } while(0)

#define ARRAY_SIZE(array)                       \
    array##_size
