#include "encrypt.h"

uint8_t *xor_encrypt(uint8_t *buf, size_t buf_len,
		     const uint8_t *key, size_t key_len)
{
	size_t i;

	for (i = 0; i < buf_len; i++)
		buf[i] ^= key[i % key_len];
	return buf;
}

uint8_t *xor_decrypt(uint8_t *buf, size_t buf_len,
		     const uint8_t *key, size_t key_len)
{
	return xor_encrypt(buf, buf_len, key, key_len);
}
