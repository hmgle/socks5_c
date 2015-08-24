#include "socks.h"
#include "socket_wrap.h"
#include "encrypt.h"

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

static void ss_fd_set_del_fd(struct ss_fd_set *fd_set, int fd, int mask)
{
	if (mask & AE_READABLE)
		FD_CLR(fd, &fd_set->rfds);
	if (mask & AE_WRITABLE)
		FD_CLR(fd, &fd_set->wfds);
}

static ssize_t _recv(int sockfd, void *buf, size_t len, int flags,
		     struct ss_conn_ctx *conn)
{
	return recv(sockfd, buf, len, flags);
}

static ssize_t decry_recv(int sockfd, void *buf, size_t len, int flags,
		          struct ss_conn_ctx *conn)
{
	ssize_t ret;

	ret = recv(sockfd, buf, len, flags);
	if (ret > 0)
		ss_decrypt(conn->encryptor, buf, buf, ret);
	return ret;
}

static ssize_t _send(int sockfd, void *buf, size_t len, int flags,
		     struct ss_conn_ctx *conn)
{
	return send(sockfd, buf, len, flags);
}

static ssize_t encry_send(int sockfd, void *buf, size_t len, int flags,
		          struct ss_conn_ctx *conn)
{
	ss_decrypt(conn->encryptor, buf, buf, len);
	return send(sockfd, buf, len, flags);
}

struct ss_server_ctx *ss_create_server(uint16_t port,
				       enum ss_encrypt_method encrypt_method,
				       const struct encry_key_s *key)
{
	struct ss_server_ctx *server;

	server = calloc(1, sizeof(typeof(*server)));
	if (server == NULL)
		return NULL;
	server->buf = buf_create(4096);
	if (server->buf == NULL)
		DIE("buf_create failed");
	server->sock_fd = create_server_socket(port);
	if (server->sock_fd < 0)
		DIE("create_server_socket failed");
	server->fd_mask = AE_READABLE;
	server->max_fd = server->sock_fd;
	if (ss_fd_set_init(&server->ss_allfd_set) < 0)
		DIE("ss_fd_set_init failed");
	if (ss_fd_set_add_fd(server->ss_allfd_set,
				server->sock_fd, AE_READABLE) < 0)
		DIE("ss_fd_set_add_fd failed");
	server->conn = calloc(1, sizeof(*server->conn));
	if (server->conn == NULL)
		DIE("calloc failed");
	INIT_LIST_HEAD(&server->conn->list);
	server->remote = calloc(1, sizeof(*server->remote));
	if (server->remote == NULL)
		DIE("calloc failed");
	INIT_LIST_HEAD(&server->remote->list);
	if (key) {
		server->encryptor = ss_create_encryptor(encrypt_method,
							key->key, key->len);
		server->ss_recv = decry_recv;
		server->ss_send = encry_send;
	} else {
		server->ss_recv = _recv;
		server->ss_send = _send;
	}
	return server;
}

struct ss_conn_ctx *ss_server_add_conn(struct ss_server_ctx *s, int conn_fd,
				int mask, struct conn_info *conn_info)
{
	struct ss_conn_ctx *new_conn;

	new_conn = calloc(1, sizeof(*new_conn));
	if (new_conn == NULL) {
		debug_print("colloc failed: %s", strerror(errno));
		return NULL;
	}
	new_conn->conn_fd = conn_fd;
	new_conn->server_entry = s;
	new_conn->fd_mask = mask;
	new_conn->ss_conn_state = OPENING;
	if (conn_info) {
		strncpy(new_conn->ss_conn_info.ip, conn_info->ip,
				sizeof(new_conn->ss_conn_info.ip) - 1);
		new_conn->ss_conn_info.ip[sizeof(new_conn->ss_conn_info.ip) - 1]
									= '\0';
		new_conn->ss_conn_info.port = conn_info->port;
	}
	list_add(&new_conn->list, &s->conn->list);
	s->conn_count++;
	s->max_fd = (conn_fd > s->max_fd) ? conn_fd : s->max_fd;
	if (ss_fd_set_add_fd(s->ss_allfd_set, conn_fd, mask) < 0)
		DIE("ss_fd_set_add_fd failed");
	if (s->encryptor) {
		new_conn->encryptor = malloc(sizeof(*new_conn->encryptor));
		memcpy(new_conn->encryptor, s->encryptor,
					sizeof(*s->encryptor));
	}
	return new_conn;
}

void ss_conn_set_handle(struct ss_conn_ctx *conn, int mask,
		ss_ioproc *r_callback, ss_ioproc *w_callback, void *para)
{
	struct io_event *event = &conn->io_proc;

	memset(event, 0, sizeof(*event));
	event->mask = mask;
	event->rfileproc = r_callback;
	event->wfileproc = w_callback;
	event->para = para;
}

/*
 * local connect server
 */
struct ss_remote_ctx *ss_conn_add_remote(struct ss_conn_ctx *conn,
		int mask, const struct conn_info *remote_info,
		struct io_event *event)
{
	struct ss_remote_ctx *new_remote;
	struct ss_server_ctx *s = conn->server_entry;

	new_remote = calloc(1, sizeof(*new_remote));
	if (new_remote == NULL) {
		debug_print("calloc failed: %s", strerror(errno));
		return NULL;
	}
	new_remote->remote_fd = client_connect(remote_info->ip,
					remote_info->port);
	if (new_remote->remote_fd < 0) {
		debug_print("client_connect() failed: %s", strerror(errno));
		return NULL;
	}
	new_remote->server_entry = s;
	new_remote->conn_entry = conn;
	new_remote->fd_mask = mask;
	if (event)
		memcpy(&new_remote->io_proc, event, sizeof(*event));
	conn->remote = new_remote;
	conn->remote_count++;
	s->max_fd = (new_remote->remote_fd > s->max_fd) ?
				new_remote->remote_fd : s->max_fd;
	if (ss_fd_set_add_fd(s->ss_allfd_set, new_remote->remote_fd, mask) < 0)
		DIE("ss_fd_set_add_fd failed");
	list_add(&new_remote->list, &s->remote->list) ;
	return new_remote;
}

void ss_server_del_conn(struct ss_server_ctx *s, struct ss_conn_ctx *conn)
{
	struct ss_remote_ctx *remote = conn->remote;

	if (conn->remote != NULL)
		remote->conn_entry = NULL;
	ss_fd_set_del_fd(s->ss_allfd_set, conn->conn_fd, conn->fd_mask);
	s->conn_count--;
	list_del(&conn->list);
	close(conn->conn_fd);
	free(conn);
}

void ss_del_remote(struct ss_server_ctx *s, struct ss_remote_ctx *remote)
{
	if (remote->conn_entry != NULL)
		remote->conn_entry->remote = NULL;
	ss_fd_set_del_fd(s->ss_allfd_set, remote->remote_fd, remote->fd_mask);
	close(remote->remote_fd);
	list_del(&remote->list);
	free(remote);
}

int ss_handshake_handle(struct ss_conn_ctx *conn)
{
	ssize_t ret;
	struct buf *buf = conn->server_entry->buf;

	ret = recv(conn->conn_fd, buf->data, 262, 0);
	if (ret <= 0)
		goto err;
	if (buf->data[0] != 0x05)
		goto err;
	/* TODO: 检查客户端支持的认证机制 */
	buf->data[0] = 0x05;
	buf->data[1] = 0x0; /* NO AUTHENTICATION REQUIRED */
	ret = send(conn->conn_fd, buf->data, 2, 0);
	if (ret != 2)
		goto err;
	conn->ss_conn_state = CONNECTING;
	return 0;
err:
	debug_print("handshake failed: %s", strerror(errno));
	ss_server_del_conn(conn->server_entry, conn);
	return -1;
}

static struct ss_requests_frame *
ss_get_requests(struct ss_requests_frame *requests, int fd,
		struct ss_conn_ctx *conn)
{
	struct ss_server_ctx *server = conn->server_entry;
	struct buf *buf = server->buf;
	ssize_t ret;

	ret = server->ss_recv(fd, buf->data, 4, 0, conn);
	if (ret != 4)
		return NULL;
	if (buf->data[0] != 0x05 || buf->data[2] != 0)
		return NULL;
	if (buf->data[1] != 0x01) {
		debug_print("only support CONNECT CMD now -_-");
		return NULL;
	}
	requests->ver = 0x05;
	requests->cmd = 0x01;
	requests->rsv = 0x0;
	switch (buf->data[3]) { /* ATYP */
	case 0x01: /* IPv4 */
		requests->atyp = 0x01;
		ret = server->ss_recv(conn->conn_fd, requests->dst_addr, 4, 0,
				      conn);
		if (ret != 4)
			return NULL;
		requests->dst_addr[ret] = '\0';
		break;
	case 0x03: /* FQDN */
		requests->atyp = 0x03;
		ret = server->ss_recv(conn->conn_fd, requests->dst_addr, 1, 0,
				      conn);
		if (ret != 1)
			return NULL;
		ret = server->ss_recv(conn->conn_fd, &requests->dst_addr[1],
				      requests->dst_addr[0], 0, conn);
		if (ret != requests->dst_addr[0])
			return NULL;
		requests->dst_addr[ret + 1] = '\0';
		break;
	case 0x04: /* IPv6 */
		requests->atyp = 0x04;
		ret = server->ss_recv(conn->conn_fd, requests->dst_addr, 16, 0,
				      conn);
		if (ret != 16)
			return NULL;
		break;
	default:
		debug_print("err ATYP: %x", buf->data[3]);
		return NULL;
	}
	ret = server->ss_recv(conn->conn_fd, requests->dst_port, 2, 0, conn);
	if (ret != 2)
		return NULL;
	return requests;
}

static struct conn_info *get_addr_info(const struct ss_requests_frame *requests,
				       struct conn_info *remote_info)
{
	struct in_addr remote_addr;
	struct hostent *hptr;
	char **pptr;
	char str[INET_ADDRSTRLEN] = {0,};
	char *addr_tmp;

	bzero(&remote_addr, sizeof(remote_addr));
	switch (requests->atyp) {
	case 0x01: /* ip v4 */
		memcpy(&remote_addr.s_addr, requests->dst_addr,
			sizeof(remote_addr.s_addr));
		sprintf(remote_info->ip, "%s", inet_ntoa(remote_addr));
		break;
	case 0x03: /* domainname */
		addr_tmp = alloca(requests->dst_addr[0] + 1);
		memcpy(addr_tmp, (char *)&requests->dst_addr[1],
				requests->dst_addr[0]);
		addr_tmp[requests->dst_addr[0]] = '\0';
		if ((hptr = gethostbyname(addr_tmp)) == NULL) {
			debug_print("gethostbyname() %s failed: %s",
				    &requests->dst_addr[1], strerror(errno));
			return NULL;
		}
		if (hptr->h_addrtype == AF_INET) {
			pptr = hptr->h_addr_list;
			for (; *pptr != NULL; pptr++) {
				sprintf(remote_info->ip, "%s",
					inet_ntop(hptr->h_addrtype, *pptr,
						str, sizeof(str)));
			}
		}
		break;
	case 0x04: /* ip v6 */
		break;
	default:
		debug_print("unknow atyp: %d", requests->atyp);
		return NULL;
	}
	remote_info->port = ntohs(*((uint16_t *)(requests->dst_port)));
	return remote_info;
}

int ss_request_handle(struct ss_conn_ctx *conn,
		struct conn_info *remote_info)
{
	/* TODO */
	struct ss_requests_frame requests;
	struct ss_server_ctx *server = conn->server_entry;
	struct buf *buf = server->buf;
	int ret;

	if (ss_get_requests(&requests, conn->conn_fd, conn) == NULL) {
		debug_print("ss_get_requests() failed: %s", strerror(errno));
		return -1;
	}
	if (get_addr_info(&requests, remote_info) == NULL) {
		debug_print("get_addr_info() failed: %s", strerror(errno));
		return -1;
	}
	buf->data[0] = 0x5;
	buf->data[1] = 0x0;
	buf->data[2] = 0x0;
	buf->data[3] = 0x1;
	int s_addr = inet_aton("0.0.0.0", NULL);
	uint32_t us_addr = htonl(s_addr);
	memcpy(&buf->data[4], &us_addr, 4);
	buf->data[4] = 0x1;
	buf->data[4 + 4] = 0x19;
	buf->data[4 + 5] = 0x19;
	buf->used = 10;
	ret = server->ss_send(conn->conn_fd, buf->data, buf->used, 0, conn);
	if (ret != buf->used) {
		debug_print("send return %d: %s", (int)ret, strerror(errno));
		return -1;
	}
	return 0;
}

static int ss_poll(struct ss_server_ctx *server)
{
	int numevents = 0;
	int retval;
	struct ss_fd_set *set = server->ss_allfd_set;
	struct ss_conn_ctx *conn;
	struct ss_remote_ctx *remote;

	memcpy(&set->_rfds, &set->rfds, sizeof(fd_set));
	memcpy(&set->_wfds, &set->wfds, sizeof(fd_set));
	retval = select(server->max_fd + 1, &set->_rfds, &set->_wfds, NULL,
			NULL);
	if (retval > 0) {
		if (FD_ISSET(server->sock_fd, &set->_rfds)) {
			server->io_proc.mask |= AE_READABLE;
			server->fd_state[numevents].type = SS_SERVER_CTX;
			server->fd_state[numevents++].ctx_ptr = server;
		}
		list_for_each_entry(conn, &server->conn->list, list) {
			if (conn->fd_mask & AE_READABLE
			    && FD_ISSET(conn->conn_fd, &set->_rfds)) {
				conn->io_proc.mask |= AE_READABLE;
				server->fd_state[numevents].type = SS_CONN_CTX;
				server->fd_state[numevents++].ctx_ptr = conn;
			}
		}
		list_for_each_entry(remote, &server->remote->list, list) {
			if (remote->fd_mask & AE_READABLE &&
			    FD_ISSET(remote->remote_fd, &set->_rfds)) {
				remote->io_proc.mask |= AE_READABLE;
				server->fd_state[numevents].type =
							SS_REMOTE_CTX;
				server->fd_state[numevents++].ctx_ptr = remote;
			}
		}
	}
	return numevents;
}

void ss_loop(struct ss_server_ctx *server)
{
	int numevents;
	struct io_event *event;
	int fd;
	int i;

	while (1) {
		numevents = ss_poll(server);
		for (i = 0; i < numevents; i++) {
			if (server->fd_state[i].type == SS_SERVER_CTX) {
				/* accept */
				event = &server->io_proc;
				fd = server->sock_fd;
			} else if (server->fd_state[i].type == SS_CONN_CTX) {
				/* recv */
				event = &((struct ss_conn_ctx *)server->
						fd_state[i].ctx_ptr)->io_proc;
				fd = ((struct ss_conn_ctx *)server->
						fd_state[i].ctx_ptr)->conn_fd;
			} else if (server->fd_state[i].type == SS_REMOTE_CTX) {
				/* recv */
				event = &((struct ss_remote_ctx *)server->
						fd_state[i].ctx_ptr)->io_proc;
				fd = ((struct ss_remote_ctx *)server->
						fd_state[i].ctx_ptr)->remote_fd;
			}
			if (event->mask & AE_READABLE &&
					event->rfileproc != NULL)
				event->rfileproc(server->fd_state[i].ctx_ptr,
						fd, event->para, event->mask);
		}
	}
}

void ss_release_server(struct ss_server_ctx *ss_server)
{
	/* TODO */
	ss_release_encryptor(ss_server->encryptor);
	free(ss_server->ss_allfd_set);
	buf_release(ss_server->buf);
	free(ss_server);
}

void ss_server_set_handle(struct ss_server_ctx *server, int mask,
			ss_ioproc *r_callback, ss_ioproc *w_callback,
			void *para)
{
	struct io_event *event = &server->io_proc;

	memset(event, 0, sizeof(*event));
	event->mask = mask;
	event->rfileproc = r_callback;
	event->wfileproc = w_callback;
	event->para = para;
}
