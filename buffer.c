#include "buffer.h"

struct buf *buf_create(size_t init_size)
{
	struct buf *ret;

	assert(init_size > 0);
	ret = malloc(sizeof(*ret));
	if (ret) {
		ret->data = calloc(init_size, sizeof(uint8_t));
		if (ret->data == NULL) {
			free(ret);
			return NULL;
		}
		ret->max = init_size;
		ret->used = 0;
	}
	return ret;
}

void buf_release(struct buf *buf)
{
	assert(buf && buf->data);
	free(buf->data);
	free(buf);
}

int buf_grow(struct buf *buf)
{
	size_t new_size;
	void *new_ptr;

	if (buf->max == 0)
		new_size = 1;
	else
		new_size = buf->max * 2;
	new_ptr = realloc(buf->data, new_size);
	if (new_ptr == NULL)
		return -1;
	buf->data = new_ptr;
	buf->max = new_size;
	return 0;
}

int buf_resize(struct buf *buf, size_t new_size)
{
	void *new_ptr;

	assert(new_size >= 0);
	if (new_size == 0) {
		free(buf->data);
		buf->max = 0;
	} else {
		new_ptr = realloc(buf->data, new_size);
		if (new_ptr == NULL)
			return -1;
		buf->data = new_ptr;
		buf->max = new_size;
	}
	return 0;
}
