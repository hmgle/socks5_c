#include "socks.h"
#include "socket_wrap.h"

static int ss_fd_set_init(struct ss_fd_set **fd_set)
{
	*fd_set = malloc(sizeof(struct ss_fd_set));

	if (*fd_set == NULL)
		return -1;
	FD_ZERO(&(*fd_set)->rfds);
	FD_ZERO(&(*fd_set)->wfds);
	return 0;
}

static int ss_fd_set_add_fd(struct ss_fd_set *fd_set, int fd, int mask)
{
	if (mask & AE_READABLE)
		FD_SET(fd, &fd_set->rfds);
	if (mask & AE_WRITABLE)
		FD_SET(fd, &fd_set->wfds);
	return 0;
}

struct ss_server_ctx *ss_create_server(uint16_t port)
{
	struct ss_server_ctx *server;

	server = calloc(1, sizeof(typeof(*server)));
	if (server == NULL)
		return NULL;
	server->sock_fd = create_server_socket(port);
	if (server->sock_fd < 0)
		DIE("create_server_socket failed!");
	server->fd_mask = AE_READABLE;
	server->max_fd = server->sock_fd;
	if (ss_fd_set_init(&server->ss_allfd_set) < 0)
		DIE("ss_fd_set_init failed!");
	if (ss_fd_set_add_fd(server->ss_allfd_set,
				server->sock_fd, AE_READABLE) < 0)
		DIE("ss_fd_set_add_fd failed!");
	server->fd_state = calloc(1, sizeof(*server->fd_state));
	if (server->fd_state == NULL)
		DIE("calloc failed!");
	server->conn = calloc(1, sizeof(*server->conn));
	if (server->conn == NULL)
		DIE("calloc failed!");
	INIT_LIST_HEAD(&server->conn->list);
	server->time_event_list = calloc(1, sizeof(*server->time_event_list));
	if (server->time_event_list == NULL)
		DIE("calloc failed!");
	INIT_LIST_HEAD(&server->time_event_list->list);
	return server;
}
