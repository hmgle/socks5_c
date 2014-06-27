#ifndef _SOCKET_WRAP_H
#define _SOCKET_WRAP_H

#include "debug.h"
#include <string.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <errno.h>

int create_server_socket(uint16_t port);
int ss_accept(int s, char *client_ip, uint16_t *client_port);
int client_connect(const char *addr, uint16_t port);

#endif
