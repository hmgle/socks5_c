#include "socket_wrap.h"
#include "socks.h"

static uint16_t server_port = 1984;

static void ss_remote_io_handle(void *remote, int fd, void *data, int mask)
{
	int readed;
	int ret;
	struct ss_remote_ctx *remote_ptr = remote;
	struct ss_conn_ctx *conn = remote_ptr->conn_entry;
	struct ss_server_ctx *server = remote_ptr->server_entry;
	struct buf *buf = server->buf;

	if (conn == NULL) {
		ss_del_remote(server, remote_ptr);
		return;
	}
	readed = recv(fd, buf->data, buf->max, MSG_DONTWAIT);
	if (readed <= 0) {
		ss_del_remote(server, remote_ptr);
		return;
	}
	ret = server->ss_send(conn->conn_fd, buf->data, readed, 0, conn);
	if (ret != readed) {
		debug_print("send return %d, should send %d: %s",
			    ret, readed, strerror(errno));
		if (ret == -1 && errno != EAGAIN) {
			debug_print("errno: %d", errno);
			ss_del_remote(server, remote_ptr);
		}
	}
}

static void client_to_remote(struct ss_conn_ctx *conn)
{
	int readed;
	int ret;
	struct ss_server_ctx *server = conn->server_entry;
	struct buf *buf = server->buf;
	struct ss_remote_ctx *remote;

	if (conn->remote == NULL) {
		ss_server_del_conn(server, conn);
		return;
	}
	readed = server->ss_recv(conn->conn_fd, buf->data, buf->max,
				 MSG_DONTWAIT, conn);
	if (readed <= 0) {
		ss_server_del_conn(server, conn);
		return;
	}
	remote = conn->remote;
	ret = send(remote->remote_fd, buf->data, readed, 0);
	if (ret != readed) {
		debug_print("send return %d, should send %d: %s",
			    ret, readed, strerror(errno));
		if (ret == -1 && errno != EAGAIN)
			ss_server_del_conn(server, conn);
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
	nc = ss_server_add_conn(s, conn_fd, AE_READABLE, &conn_info);
	if (nc == NULL) {
		debug_print("ss_server_add_conn failed: %s", strerror(errno));
		return;
	}
	ss_conn_set_handle(nc, AE_READABLE, ss_io_handle, NULL, NULL);
}

int main(int argc, char **argv)
{
	struct ss_server_ctx *ss_s;
	enum ss_encrypt_method encry_method = NO_ENCRYPT;
	struct encry_key_s *key = NULL;
	size_t key_len;
	int opt;

	while ((opt = getopt(argc, argv, "p:m:e:h?")) != -1) {
		switch (opt) {
		case 'p':
			server_port = atoi(optarg);
			break;
		case 'm':
			if (!strcmp("xor", optarg))
				encry_method = XOR_METHOD;
			else if (!strcmp("rc4", optarg))
				encry_method = RC4_METHOD;
			break;
		case 'e':
			key_len = strlen(optarg);
			key = malloc(sizeof(*key) + key_len);
			key->len = key_len;
			memcpy(key->key, optarg, key_len);
			break;
		default:
			fprintf(stderr,
				"usage: %s [-p server_port] [-m xor|rc4] "
				"[-e key]\n",
				argv[0]);
			exit(1);
		}
	}
	ss_s = ss_create_server(server_port, encry_method, key);
	if (ss_s == NULL)
		DIE("ss_create_server failed!");
	ss_server_set_handle(ss_s, AE_READABLE, ss_accept_handle, NULL, NULL);
	ss_loop(ss_s);
	ss_release_server(ss_s);
	return 0;
}
