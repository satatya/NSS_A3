#ifndef CRYPTO_UTIL_H
#define CRYPTO_UTIL_H

#include <stddef.h>

int derive_file_key(const unsigned char *session_key, size_t session_key_len,
                    unsigned char *out_key, size_t out_len);

/* Returns ciphertext length on success, -1 on failure. */
int aes_gcm_encrypt(const unsigned char *key,
                    const unsigned char *nonce, size_t nonce_len,
                    const unsigned char *aad, size_t aad_len,
                    const unsigned char *plaintext, size_t pt_len,
                    unsigned char *ciphertext,
                    unsigned char *tag, size_t tag_len);

/* Returns plaintext length on success,
 * -2 on tag verification failure (tampering),
 * -1 on other errors. */
int aes_gcm_decrypt(const unsigned char *key,
                    const unsigned char *nonce, size_t nonce_len,
                    const unsigned char *aad, size_t aad_len,
                    const unsigned char *ciphertext, size_t ct_len,
                    const unsigned char *tag, size_t tag_len,
                    unsigned char *plaintext);

#endif
