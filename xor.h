#ifndef _XOR_H
#define _XOR_H

#include <stdint.h>
#include <stdlib.h>

struct xor_encryptor {
	size_t encry_loc; /* 加密同步用 */
	size_t decry_loc; /* 解密同步用 */
	size_t key_len;
	uint8_t key[0];
};

uint8_t *xor_encrypt(uint8_t *buf, size_t buf_len,
		     const uint8_t *key, size_t key_len, size_t *loc);
uint8_t *xor_decrypt(uint8_t *buf, size_t buf_len,
		     const uint8_t *key, size_t key_len, size_t *loc);

#endif
