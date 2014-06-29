#ifndef _ENCRYPT_H
#define _ENCRYPT_H

#include <stdint.h>
#include <stdlib.h>

uint8_t *xor_encrypt(uint8_t *buf, size_t buf_len, 
		     const uint8_t *key, size_t key_len, size_t *loc);
uint8_t *xor_decrypt(uint8_t *buf, size_t buf_len, 
		     const uint8_t *key, size_t key_len, size_t *loc);
#endif
