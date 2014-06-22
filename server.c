#include "socket_wrap.h"
#include "socks.h"

static void ss_accept_handle(void *s, int fd, void *data, int mask)
{
	int conn_fd;
	struct conn_info conn_info;
	struct ss_conn_ctx *nc;

	conn_fd = ss_accept(fd, conn_info.ip, &conn_info.port);
	if (conn_fd < 0) {
		debug_print("ss_accetp failed!");
		return;
	}
	nc = ss_server_add_conn(s, conn_fd, AE_READABLE, &conn_info, data);
	if (nc == NULL) {
		debug_print("ss_server_add_conn failed!");
		return;
	}
}

static void ss_remote_io_handle(void *remote, int fd, void *data, int mask)
{
	int readed;
	int ret;
	struct ss_remote_ctx *remote_ptr = remote;
	struct buf *buf = remote_ptr->conn_entry->msg;

	readed = recv(fd, buf->data, buf->max, MSG_DONTWAIT);
	if (readed <= 0) {
		ss_conn_del_remote(remote_ptr->conn_entry, remote_ptr);
		return;
	}
	ret = send(remote_ptr->conn_entry->conn_fd, buf->data, readed,
			MSG_DONTWAIT);
	if (ret != readed)
		debug_print("send return %d, should send %d", ret, readed);
}

static struct ss_remote_ctx *trace_entry(const struct ss_remote_ctx *trace,
					int n)
{
	struct ss_remote_ctx *pos;
	int i = 0;

	list_for_each_entry(pos, &trace->list, list) {
		if (i == n)
			return pos;
		i++;
	}
	return NULL;
}

static void client_to_remote(struct ss_conn_ctx *conn)
{
	int readed;
	int ret;
	struct buf *buf = conn->msg;
	struct ss_remote_ctx *remote;

	readed = recv(conn->conn_fd, buf->data, buf->max, MSG_DONTWAIT);
	if (readed <= 0) {
		ss_server_del_conn(conn->server_entry, conn);
		return;
	}
	remote = trace_entry(conn->remote, 0);
	ret = send(remote->remote_fd, buf->data, readed, MSG_DONTWAIT);
	if (ret != readed)
		debug_print("send return %d, should send %d", ret, readed);
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
		.mask = AE_READABLE | AE_WRITABLE,
		.rfileproc = ss_remote_io_handle, /* server 可读 */
		.wfileproc = NULL,
		.para = NULL,
	};

	switch (conn_ptr->ss_conn_state) {
	case OPENING: /* reply */
		ret = ss_request_handle(conn_ptr, &remote_info);
		if (ret < 0)
			goto err;
		ss_conn_add_remote(conn_ptr, AE_READABLE | AE_WRITABLE,
				&remote_info, &event);
		break;
	case CONNECTING: /* forwarding */
		client_to_remote(conn_ptr);
		break;
	default:
		debug_print("unknow status");
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

	ss_s = ss_create_server(8388);
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
