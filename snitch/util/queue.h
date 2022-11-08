#pragma once

#include "util.h"

typedef struct node_s node_t;

struct node_s {
	u8     *val;
	node_t *next;
};

typedef struct queue_s {
	i32 size;
	i32 capacity;
	node_t *head;
	node_t *tail;
} queue_t;

queue_t *queue_init(i32 capacity) {
	queue_t *q;
 	MALLOC(q, sizeof(*q));
	q->size = 0;
	q->capacity = capacity;
	q->head = NULL;
	q->tail = NULL;
	return q;
}

i32 queue_put(queue_t *q, u8 *val) {
	if (q->size == q->capacity)
		return 1;
	node_t *n;
	MALLOC(n, sizeof(*n));
	n->val = val;
	n->next = NULL;
	if (!q->head) {
		q->head = n;
		q->tail = n;
		q->size = 1;
		return 0;
	}
	q->tail->next = n;
	q->tail = n;
	q->size++;
	return 0;
}

u8 *queue_get(queue_t *q) {
	if (!q->size)
		return NULL;
	node_t *n = q->head;
	u8 *val = n->val;
	q->head = n->next;
	free(n);
	q->size--;
	return val;
}
