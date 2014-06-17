#include "socket_wrap.h"
#include "socks.h"

int main(int argc, char **argv)
{
	struct ss_server_ctx *lo_s;

	lo_s = ss_create_server(1080);
	if (lo_s == NULL)
		DIE("ss_create_server failed!");
	return 0;
}
