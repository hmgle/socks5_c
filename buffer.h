#ifndef _BUFFER_H
#define _BUFFER_H

#include <assert.h>
#include <stdlib.h>
#include <stdint.h>

struct buf {
	size_t max;
	size_t used;
	uint8_t *data;
};

struct buf *buf_create(size_t init_size);
void buf_release(struct buf *buf);
int buf_grow(struct buf *buf);
int buf_resize(struct buf *buf, size_t newsize);

#endif
