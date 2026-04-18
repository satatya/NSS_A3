#include "crypto_util.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <string.h>
#include <stdio.h>

#define HKDF_INFO "sfc-file-transfer"

int derive_file_key(const unsigned char *session_key, size_t session_key_len,
                    unsigned char *out_key, size_t out_len) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) return -1;

    int ret = -1;
    size_t len = out_len;
    if (EVP_PKEY_derive_init(pctx) <= 0) goto done;
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) goto done;
    /* salt left empty — default zero-filled salt is fine because the IKM
     * (the Kerberos session key) is already a strong cryptographic key. */
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, session_key,
                                   (int)session_key_len) <= 0) goto done;
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, (unsigned char *)HKDF_INFO,
                                    (int)strlen(HKDF_INFO)) <= 0) goto done;
    if (EVP_PKEY_derive(pctx, out_key, &len) <= 0) goto done;
    if (len != out_len) goto done;

    ret = 0;
done:
    EVP_PKEY_CTX_free(pctx);
    return ret;
}

int aes_gcm_encrypt(const unsigned char *key,
                    const unsigned char *nonce, size_t nonce_len,
                    const unsigned char *aad, size_t aad_len,
                    const unsigned char *plaintext, size_t pt_len,
                    unsigned char *ciphertext,
                    unsigned char *tag, size_t tag_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int ret = -1, len = 0, total = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            (int)nonce_len, NULL) != 1) goto done;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto done;

    if (aad && aad_len > 0) {
        if (EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) goto done;
    }
    if (EVP_EncryptUpdate(ctx, ciphertext, &len,
                          plaintext, (int)pt_len) != 1) goto done;
    total = len;
    if (EVP_EncryptFinal_ex(ctx, ciphertext + total, &len) != 1) goto done;
    total += len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                            (int)tag_len, tag) != 1) goto done;
    ret = total;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int aes_gcm_decrypt(const unsigned char *key,
                    const unsigned char *nonce, size_t nonce_len,
                    const unsigned char *aad, size_t aad_len,
                    const unsigned char *ciphertext, size_t ct_len,
                    const unsigned char *tag, size_t tag_len,
                    unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int ret = -1, len = 0, total = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            (int)nonce_len, NULL) != 1) goto done;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto done;

    if (aad && aad_len > 0) {
        if (EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) goto done;
    }
    if (EVP_DecryptUpdate(ctx, plaintext, &len,
                          ciphertext, (int)ct_len) != 1) goto done;
    total = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                            (int)tag_len, (void *)tag) != 1) goto done;

    /* EVP_DecryptFinal_ex returns 1 if tag is valid, 0 if it fails.
     * We MUST check this before treating plaintext as authenticated. */
    if (EVP_DecryptFinal_ex(ctx, plaintext + total, &len) != 1) {
        ret = -2;          /* tampering */
        goto done;
    }
    total += len;
    ret = total;
done:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}
