#include "encrypt.h"
#include "debug.h"

struct ss_encryptor *ss_create_encryptor(enum ss_encrypt_method method,
					 const uint8_t *key, size_t key_len)
{
	struct ss_encryptor *encryptor;

	switch (method) {
	case XOR_METHOD:
		encryptor = calloc(1, sizeof(typeof(*encryptor)) + key_len);
		encryptor->enc_method = method;
		encryptor->xor_enc.key_len = key_len;
		memcpy(encryptor->xor_enc.key, key, key_len);
		return encryptor;
	case RC4_METHOD:
		encryptor = calloc(1, sizeof(typeof(*encryptor)) + key_len);
		encryptor->enc_method = method;
		encryptor->rc4_enc.key_len = key_len;
		memcpy(encryptor->rc4_enc.key, key, key_len);
		rc4_init(&encryptor->rc4_enc.en_state, key, key_len);
		rc4_init(&encryptor->rc4_enc.de_state, key, key_len);
		return encryptor;
	default:
		DIE("not support %d", method);
	}
}

void ss_release_encryptor(struct ss_encryptor *encryptor)
{
	free(encryptor);
}

uint8_t *ss_encrypt(struct ss_encryptor *encryptor, uint8_t *dest,
		    uint8_t *src, size_t src_len)
{
	switch (encryptor->enc_method) {
	case XOR_METHOD:
		if (dest == src)
			return xor_encrypt(src, src_len,
					encryptor->xor_enc.key,
					encryptor->xor_enc.key_len,
					&encryptor->xor_enc.encry_loc);
		else {
			memcpy(dest, src, src_len);
			return xor_encrypt(dest, src_len,
					encryptor->xor_enc.key,
					encryptor->xor_enc.key_len,
					&encryptor->xor_enc.encry_loc);
		}
		break;
	case RC4_METHOD:
		rc4_crypt(&encryptor->rc4_enc.en_state, src, dest, src_len);
		return dest;
	default:
		DIE("not support %d", encryptor->enc_method);
	}
}

uint8_t *ss_decrypt(struct ss_encryptor *decryptor, uint8_t *dest,
		    uint8_t *src, size_t src_len)
{
	switch (decryptor->enc_method) {
	case XOR_METHOD:
		if (dest == src)
			return xor_decrypt(src, src_len,
					decryptor->xor_enc.key,
					decryptor->xor_enc.key_len,
					&decryptor->xor_enc.decry_loc);
		else {
			memcpy(dest, src, src_len);
			return xor_decrypt(dest, src_len,
					decryptor->xor_enc.key,
					decryptor->xor_enc.key_len,
					&decryptor->xor_enc.decry_loc);
		}
		break;
	case RC4_METHOD:
		rc4_crypt(&decryptor->rc4_enc.de_state, src, dest, src_len);
		return dest;
	default:
		DIE("not support %d", decryptor->enc_method);
	}
}
