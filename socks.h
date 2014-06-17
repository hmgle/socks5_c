#ifndef _SOCKES_H
#define _SOCKES_H

#include <stdint.h>
#include <stdlib.h>

struct ss_server_ctx {
	int sock_fd;
	uint8_t buf[4096];
};

struct ss_server_ctx *ss_create_server(uint16_t port);

#endif
