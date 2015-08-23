#ifndef _ENCRYPT_H
#define _ENCRYPT_H

#include "xor.h"

enum ss_encrypt_method {
	NO_ENCRYPT = 0,
	XOR_METHOD = 1,
};

struct ss_encryptor {
	enum ss_encrypt_method enc_method;
	union {
		struct xor_encryptor xor_enc;
	};
};

struct ss_encryptor *ss_create_encryptor(enum ss_encrypt_method method,
					 const uint8_t *key, size_t key_len);
void ss_release_encryptor(struct ss_encryptor *encryptor);
uint8_t *ss_encrypt(struct ss_encryptor *encryptor, uint8_t *dest,
		    uint8_t *src, size_t src_len);
uint8_t *ss_decrypt(struct ss_encryptor *decryptor, uint8_t *dest,
		    uint8_t *src, size_t src_len);
#endif
