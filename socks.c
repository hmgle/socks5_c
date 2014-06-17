#include "socks.h"

struct ss_server_ctx *ss_create_server(uint16_t port)
{
	struct ss_server_ctx *server;

	server = calloc(1, sizeof(typeof(*server)));
	if (server == NULL)
		return NULL;
	return server;
}
