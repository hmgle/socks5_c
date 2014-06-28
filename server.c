#include "socket_wrap.h"
#include "socks.h"

static uint16_t server_port = 8388;

static void ss_accept_handle(void *s, int fd, void *data, int mask)
{
	int conn_fd;
	struct conn_info conn_info;
	struct ss_conn_ctx *nc;

	conn_fd = ss_accept(fd, conn_info.ip, &conn_info.port);
	if (conn_fd < 0) {
		debug_print("ss_accetp failed: %s", strerror(errno));
		return;
	}
	nc = ss_server_add_conn(s, conn_fd, AE_READABLE, &conn_info, data);
	if (nc == NULL) {
		debug_print("ss_server_add_conn failed: %s", strerror(errno));
		return;
	}
}

static void ss_remote_io_handle(void *remote, int fd, void *data, int mask)
{
	int readed;
	int ret;
	struct ss_remote_ctx *remote_ptr = remote;
	struct ss_conn_ctx *conn = remote_ptr->conn_entry;
	struct buf *buf = remote_ptr->server_entry->buf;

	if (conn == NULL) {
		ss_del_remote(remote_ptr->server_entry, remote_ptr);
		return;
	}
	readed = recv(fd, buf->data, buf->max, MSG_DONTWAIT);
	if (readed <= 0) {
		ss_del_remote(remote_ptr->server_entry, remote_ptr);
		return;
	}
	ret = send(remote_ptr->conn_entry->conn_fd, buf->data, readed,
			MSG_DONTWAIT);
	if (ret != readed) {
		debug_print("send return %d, should send %d: %s",
			    ret, readed, strerror(errno));
		if (ret == -1 && errno != EAGAIN) {
			debug_print("errno: %d", errno);
			ss_del_remote(remote_ptr->server_entry, remote_ptr);
		}
	}
}

static void client_to_remote(struct ss_conn_ctx *conn)
{
	int readed;
	int ret;
	struct buf *buf = conn->server_entry->buf;
	struct ss_remote_ctx *remote;

	if (conn->remote == NULL) {
		ss_server_del_conn(conn->server_entry, conn);
		return;
	}
	readed = recv(conn->conn_fd, buf->data, buf->max, MSG_DONTWAIT);
	if (readed <= 0) {
		ss_server_del_conn(conn->server_entry, conn);
		return;
	}
	remote = conn->remote;
	ret = send(remote->remote_fd, buf->data, readed, MSG_DONTWAIT);
	if (ret != readed) {
		debug_print("send return %d, should send %d: %s",
			    ret, readed, strerror(errno));
		if (ret == -1 && errno != EAGAIN)
			ss_server_del_conn(conn->server_entry, conn);
	}
}

/*
 * read from local
 */
static void ss_io_handle(void *conn, int fd, void *data, int mask)
{
	/* TODO */
	struct ss_conn_ctx *conn_ptr = conn;
	int ret;
	struct conn_info remote_info;
	struct io_event event = {
		.mask = AE_READABLE,
		.rfileproc = ss_remote_io_handle, /* server 可读 */
		.wfileproc = NULL,
		.para = NULL,
	};

	switch (conn_ptr->ss_conn_state) {
	case OPENING: /* reply */
		ret = ss_request_handle(conn_ptr, &remote_info);
		if (ret < 0)
			goto err;
		if (ss_conn_add_remote(conn_ptr, AE_READABLE,
				&remote_info, &event) == NULL) {
			debug_print("ss_conn_add_remote() failed: %s",
				    strerror(errno));
			goto err;
		}
		conn_ptr->ss_conn_state = CONNECTING;
		break;
	case CONNECTING: /* forwarding */
		client_to_remote(conn_ptr);
		break;
	default:
		debug_print("unknow status: %d", conn_ptr->ss_conn_state);
		goto err;
	}
	return;
err:
	debug_print("close");
	ss_server_del_conn(conn_ptr->server_entry, conn_ptr);
}

int main(int argc, char **argv)
{
	struct ss_server_ctx *ss_s;
	struct io_event s_event;
	struct io_event c_event;
	int opt;

	while ((opt = getopt(argc, argv, "p:h?")) != -1) {
		switch (opt) {
		case 'p':
			server_port = atoi(optarg);
			break;
		default:
			fprintf(stderr,
				"usage: %s [-p server_port]\n", argv[0]);
			exit(1);
		}
	}
	ss_s = ss_create_server(server_port, NULL);
	if (ss_s == NULL)
		DIE("ss_create_server failed!");
	memset(&s_event, 0, sizeof(s_event));
	s_event.rfileproc = ss_accept_handle;
	memset(&c_event, 0, sizeof(c_event));
	c_event.rfileproc = ss_io_handle;
	s_event.para = malloc(sizeof(c_event));
	memcpy(s_event.para, &c_event, sizeof(c_event));
	memcpy(&ss_s->io_proc, &s_event, sizeof(s_event));

	ss_loop(ss_s);
	ss_release_server(ss_s);
	return 0;
}
