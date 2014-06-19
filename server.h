#ifndef _SERVER_H
#define _SERVER_H

#include "socks.h"

struct client {
	struct ss_conn_ctx *conn;
	int client_id;
	struct list_head list;
};

#endif
