#include "socket_wrap.h"

static int bind_server(int server_s, char *server_ip, uint16_t server_port)
{
	struct sockaddr_in server_sockaddr;

	memset(&server_sockaddr, 0, sizeof server_sockaddr);
	server_sockaddr.sin_family = AF_INET;
	if (server_ip != NULL)
		inet_aton(server_ip, &server_sockaddr.sin_addr);
	else
		server_sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	server_sockaddr.sin_port = htons(server_port);
	return bind(server_s, (struct sockaddr *) &server_sockaddr,
			sizeof(server_sockaddr));
}

static inline int fd_set_noblock(int fd)
{
	int flags;

	flags = fcntl(fd, F_GETFL);
	if (flags == -1)
		return -1;

	flags |= O_NONBLOCK;
	flags = fcntl(fd, F_SETFL, flags);
	return flags;
}

int create_server_socket(uint16_t port)
{
	int server_s;
	int sock_opt = 1;
	int ret;

	server_s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (server_s == -1)
		DIE("unable to create socket");

	/* accept fd must set noblock for rst */
	ret = fd_set_noblock(server_s);
	if (ret < 0)
		DIE("fd_set_noblock failed");

	/* close server socket on exec so cgi's can't write to it */
	if (fcntl(server_s, F_SETFD, 1) == -1)
		DIE("can't set close-on-exec");

	if ((setsockopt(server_s, SOL_SOCKET, SO_REUSEADDR, (void *)&sock_opt,
			sizeof(sock_opt))) == -1)
		DIE("setsockopt failed");

	/* internet family-specific code encapsulated in bind_server()  */
	if (bind_server(server_s, NULL, port) == -1)
		DIE("unable to bind");

	if (listen(server_s, 100) == -1)
		DIE("unable to listen");
	return server_s;
}

int ss_accept(int s, char *client_ip, uint16_t *client_port)
{
	int fd;
	struct sockaddr_in sa;
	socklen_t salen = sizeof(sa);

	if ((fd = accept(s, (struct sockaddr *)&sa, &salen)) < 0)
		return -1;
	if (client_ip)
		strcpy(client_ip, inet_ntoa(sa.sin_addr));
	if (client_port)
		*client_port = ntohs(sa.sin_port);
	return fd;
}

int client_connect(const char *addr, uint16_t port)
{
	int s;
	struct sockaddr_in sa;

	if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		return -1;

	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	if (inet_aton(addr, &sa.sin_addr) == 0) {
		struct hostent *he;

		/*
		 * FIXME: it may block!
		 * not support IPv6. getarrrinfo() is better.
		 */
		he = gethostbyname(addr);
		if (he == NULL) {
			debug_print("can't resolve: %s: %s",
				    addr, strerror(errno));
			close(s);
			return -1;
		}
		memcpy(&sa.sin_addr, he->h_addr, sizeof(struct in_addr));
	}
	/* FIXME: it may block! */
	if (connect(s, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
		debug_print("connect failed: %s", strerror(errno));
		close(s);
		return -1;
	}
	return s;
}
