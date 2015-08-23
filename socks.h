#ifndef _SOCKES_H
#define _SOCKES_H

#include "list.h"
#include "debug.h"
#include "socks5_protocol.h"
#include "buffer.h"
#include "encrypt.h"
#include <stdint.h>
#include <stdlib.h>
#include <sys/select.h>

#define AE_NONE 0
#define AE_READABLE 1
#define AE_WRITABLE 2
#define AE_NOMORE -1

struct ss_server_ctx;

struct conn_info {
	char ip[128];
	uint16_t port;
};

struct ss_fd_set {
	fd_set rfds, wfds;
	/* We need to have a copy of the fd sets as it's not safe to reuse
	 * FD sets after select(). */
	fd_set _rfds, _wfds;
};

typedef void ss_ioproc(void *owner, int fd, void *para, int mask);

struct io_event {
	int mask; /* one of AE_(READABLE|WRITABLE) */
	ss_ioproc *rfileproc;
	ss_ioproc *wfileproc;
	void *para;
};

#define SS_SERVER_CTX 1
#define SS_CONN_CTX 2
#define SS_REMOTE_CTX 3

struct fd_curr_state {
	int type;
	void *ctx_ptr;
};

struct ss_remote_ctx {
	int remote_fd;
	struct ss_server_ctx *server_entry;
	struct ss_conn_ctx *conn_entry;
	int fd_mask; /* one of AE_(READABLE|WRITABLE) */
	struct io_event io_proc;
	struct list_head list;
};

struct ss_conn_ctx {
	int conn_fd;
	struct ss_server_ctx *server_entry;
	int fd_mask; /* one of AE_(READABLE|WRITABLE) */
	enum ss_state ss_conn_state;
	struct conn_info ss_conn_info;
	struct io_event io_proc;
	struct list_head list;
	int remote_count;
	struct ss_remote_ctx *remote;
	struct ss_encryptor *encryptor;
};

struct encry_key_s {
	size_t len;
	uint8_t key[0];
};

struct ss_server_ctx {
	int sock_fd;
	int fd_mask; /* one of AE_(READABLE|WRITABLE) */
	uint16_t s_port;
	uint32_t s_addr;
	int conn_count; /* 连接数 */
	struct ss_conn_ctx *conn;
	struct ss_remote_ctx *remote;
	struct io_event io_proc;
	struct buf *buf;
	int max_fd;
	struct ss_fd_set *ss_allfd_set;
	struct fd_curr_state fd_state[1024 * 10];
	struct ss_encryptor *encryptor;
	ssize_t (*ss_recv)(int sockfd, void *buf, size_t len, int flags,
			   struct ss_conn_ctx *conn);
	ssize_t (*ss_send)(int sockfd, void *buf, size_t len, int flags,
			   struct ss_conn_ctx *conn);
};

struct ss_server_ctx *ss_create_server(uint16_t port,
				       enum ss_encrypt_method encrypt_method,
				       const struct encry_key_s *key);
void ss_release_server(struct ss_server_ctx *ss_server);
struct ss_conn_ctx *ss_server_add_conn(struct ss_server_ctx *s, int conn_fd,
				int mask, struct conn_info *conn_info);
struct ss_remote_ctx *ss_conn_add_remote(struct ss_conn_ctx *conn, int mask,
		const struct conn_info *remote_info,
		struct io_event *event);
void ss_server_del_conn(struct ss_server_ctx *s, struct ss_conn_ctx *conn);
void ss_del_remote(struct ss_server_ctx *s, struct ss_remote_ctx *remote);
int ss_handshake_handle(struct ss_conn_ctx *conn);
int ss_request_handle(struct ss_conn_ctx *conn,
		struct conn_info *remote_info);
void ss_loop(struct ss_server_ctx *server);
void ss_server_set_handle(struct ss_server_ctx *server, int mask,
		ss_ioproc *r_callback, ss_ioproc *w_callback, void *para);
void ss_conn_set_handle(struct ss_conn_ctx *conn, int mask,
		ss_ioproc *r_callback, ss_ioproc *w_callback, void *para);

#endif
