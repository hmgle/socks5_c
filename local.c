#include "socket_wrap.h"
#include "socks.h"

static char *remote_ip = "127.0.0.1";
static uint16_t remote_port = 1984;
static uint16_t listen_port = 2080;

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
	readed = server->ss_recv(fd, buf->data, buf->max, MSG_DONTWAIT, conn);
	if (readed <= 0) {
		ss_del_remote(server, remote_ptr);
		return;
	}
	ret = send(conn->conn_fd, buf->data, readed, 0);
	if (ret != readed) {
		debug_print("send return %d, should send %d: %s",
			    ret, readed, strerror(errno));
		if (ret == -1 && errno != EAGAIN)
			ss_del_remote(remote_ptr->server_entry, remote_ptr);
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
	readed = recv(conn->conn_fd, buf->data, buf->max, MSG_DONTWAIT);
	if (readed <= 0) {
		ss_server_del_conn(server, conn);
		return;
	}
	remote = conn->remote;
	ret = server->ss_send(remote->remote_fd, buf->data, readed, 0, conn);
	if (ret != readed) {
		debug_print("send return %d, should send %d: %s",
			    ret, readed, strerror(errno));
		if (ret == -1 && errno != EAGAIN)
			ss_server_del_conn(server, conn);
	}
}

static void ss_io_handle(void *conn, int fd, void *data, int mask)
{
	struct ss_conn_ctx *conn_ptr = conn;
	struct conn_info remote_info;
	struct io_event event = {
		.mask = AE_READABLE,
		.rfileproc = ss_remote_io_handle, /* server 可读 */
		.wfileproc = NULL,
		.para = NULL,
	};

	strncpy(remote_info.ip, remote_ip, sizeof(remote_info.ip));
	remote_info.port = remote_port;
	switch (conn_ptr->ss_conn_state) {
	case OPENING:
		if (ss_handshake_handle(conn_ptr) < 0)
			return;
		if (ss_conn_add_remote(conn_ptr, AE_READABLE,
				&remote_info, &event) == NULL) {
			debug_print("ss_conn_add_remote() failed: %s",
				    strerror(errno));
			goto err;
		}
		conn_ptr->ss_conn_state = CONNECTING;
		break;
	case CONNECTING:
	case CONNECTED:
		/* TODO */
		client_to_remote(conn_ptr);
		break;
	default:
		debug_print("unknow state: %d", conn_ptr->ss_conn_state);
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
	struct ss_server_ctx *lo_s;
	enum ss_encrypt_method encry_method = NO_ENCRYPT;
	struct encry_key_s *key = NULL;
	size_t key_len;
	int opt;

	while ((opt = getopt(argc, argv, "l:p:s:m:e:h?")) != -1) {
		switch (opt) {
		case 'l':
			remote_ip = optarg;
			break;
		case 'p':
			remote_port = atoi(optarg);
			break;
		case 's':
			listen_port = atoi(optarg);
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
				"usage: %s [-l remote_ip] "
				"[-p remote_port] [-s listen_port] "
				"[-m xor|rc4] [-e key]\n",
				argv[0]);
			exit(1);
		}
	}
	lo_s = ss_create_server(listen_port, encry_method, key);
	if (lo_s == NULL)
		DIE("ss_create_server failed!");
	ss_server_set_handle(lo_s, AE_READABLE, ss_accept_handle, NULL, NULL);
	ss_loop(lo_s);
	ss_release_server(lo_s);
	return 0;
}
