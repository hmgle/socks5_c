#ifndef _SOCKS5_PROTOCOL_H
#define _SOCKS5_PROTOCOL_H

#include <stdint.h>

enum ss_state {
	OPENING = 0,
	CONNECTING,
	CONNECTED,
};

struct ss_requests_frame {
	uint8_t ver;
	uint8_t cmd;
	uint8_t rsv;
	uint8_t atyp;
	uint8_t dst_addr[256];
	uint8_t dst_port[2];
};

struct ss_replies_frame {
	uint8_t ver;
	uint8_t rep;
	uint8_t rsv;
	uint8_t atyp;
	uint8_t dst_addr[256];
	uint8_t dst_port[2];
};

#endif
