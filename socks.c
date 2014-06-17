#include "socks.h"

struct ss_server_ctx *ss_create_server(uint16_t port)
{
	struct ss_server_ctx *server;

	server = calloc(1, sizeof(typeof(*server)));
	if (server == NULL)
		return NULL;
	server->sock_fd = create_server_socket(port);
	if (server->sock_fd < 0)
		DIE("create_server_socket failed!");
	return server;
}
