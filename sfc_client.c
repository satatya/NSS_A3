#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdint.h>

#include <gssapi/gssapi.h>
#include <gssapi/gssapi_generic.h>
#include <openssl/rand.h>

#include "netutil.h"
#include "gss_util.h"
#include "crypto_util.h"

#define NONCE_LEN    12
#define TAG_LEN      16
#define FILE_KEY_LEN 32

static int connect_to_server(const char *host, int port) {
    struct hostent *he = gethostbyname(host);
    if (!he) { fprintf(stderr, "gethostbyname(%s) failed\n", host); return -1; }
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); return -1; }
    struct sockaddr_in addr = { .sin_family = AF_INET,
                                .sin_port   = htons(port) };
    memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect"); close(sock); return -1;
    }
    return sock;
}

static int establish_client_ctx(int sock, const char *service_name_str,
                                gss_ctx_id_t *out_ctx) {
    OM_uint32 maj, min;
    gss_name_t target = GSS_C_NO_NAME;
    gss_buffer_desc name_buf, send_tok = GSS_C_EMPTY_BUFFER,
                    recv_tok = GSS_C_EMPTY_BUFFER;
    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;

    name_buf.value  = (void *)service_name_str;
    name_buf.length = strlen(service_name_str);
    maj = gss_import_name(&min, &name_buf,
                          (gss_OID)GSS_C_NT_HOSTBASED_SERVICE, &target);
    if (GSS_ERROR(maj)) {
        display_gss_error("gss_import_name", maj, min);
        return -1;
    }

    gss_buffer_desc *in_tok = GSS_C_NO_BUFFER;
    do {
        maj = gss_init_sec_context(&min, GSS_C_NO_CREDENTIAL, &ctx, target,
                                   GSS_C_NO_OID,
                                   GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG,
                                   0, GSS_C_NO_CHANNEL_BINDINGS,
                                   in_tok, NULL, &send_tok, NULL, NULL);

        if (send_tok.length > 0) {
            if (send_token(sock, send_tok.value, send_tok.length) < 0) {
                gss_release_buffer(&min, &send_tok);
                gss_release_name(&min, &target);
                return -1;
            }
            gss_release_buffer(&min, &send_tok);
        }
        if (GSS_ERROR(maj)) {
            display_gss_error("gss_init_sec_context", maj, min);
            gss_release_name(&min, &target);
            return -1;
        }
        if (recv_tok.value) { free(recv_tok.value); recv_tok.value = NULL; }

        if (maj == GSS_S_CONTINUE_NEEDED) {
            if (recv_token(sock, &recv_tok.value, &recv_tok.length) < 0) {
                gss_release_name(&min, &target);
                return -1;
            }
            in_tok = &recv_tok;
        }
    } while (maj == GSS_S_CONTINUE_NEEDED);

    if (recv_tok.value) free(recv_tok.value);
    gss_release_name(&min, &target);
    *out_ctx = ctx;
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <server_host> <port> <filepath>\n", argv[0]);
        return 1;
    }
    const char *server_host = argv[1];
    int port = atoi(argv[2]);
    const char *filepath = argv[3];

    int sock = connect_to_server(server_host, port);
    if (sock < 0) return 1;

    /* The service name "sfc@servervm.myrealm.com" maps to the
     * service principal sfc/servervm.myrealm.com@MYREALM.COM */
    char service_name[256];
    snprintf(service_name, sizeof(service_name), "sfc@%s", server_host);

    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
    if (establish_client_ctx(sock, service_name, &ctx) < 0) {
        close(sock); return 1;
    }
    printf("[CLIENT] GSS context established with %s\n", service_name);

    /* Extract session key and derive K_file */
    unsigned char *session_key = NULL;
    size_t session_key_len = 0;
    if (extract_session_key(ctx, &session_key, &session_key_len) < 0) {
        close(sock); return 1;
    }
    printf("[CLIENT] Extracted %zu-byte Kerberos session key\n", session_key_len);

    unsigned char file_key[FILE_KEY_LEN];
    if (derive_file_key(session_key, session_key_len,
                        file_key, FILE_KEY_LEN) < 0) {
        fprintf(stderr, "HKDF failed\n"); return 1;
    }
    memset(session_key, 0, session_key_len);
    free(session_key);
    printf("[CLIENT] Derived K_file via HKDF-SHA256 (info=\"sfc-file-transfer\")\n");

    /* Read the input file into memory */
    FILE *fp = fopen(filepath, "rb");
    if (!fp) { perror("fopen"); return 1; }
    fseek(fp, 0, SEEK_END);
    long fsz = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (fsz < 0) { fclose(fp); return 1; }
    size_t pt_len = (size_t)fsz;
    unsigned char *plaintext = malloc(pt_len > 0 ? pt_len : 1);
    if (pt_len > 0 && fread(plaintext, 1, pt_len, fp) != pt_len) {
        perror("fread"); return 1;
    }
    fclose(fp);

    /* Use the basename as AAD — it is integrity-protected but sent in clear */
    const char *slash = strrchr(filepath, '/');
    const char *basename = slash ? slash + 1 : filepath;
    size_t basename_len = strlen(basename);

    /* Generate a fresh random 12-byte nonce */
    unsigned char nonce[NONCE_LEN];
    if (RAND_bytes(nonce, NONCE_LEN) != 1) {
        fprintf(stderr, "RAND_bytes failed\n"); return 1;
    }

    unsigned char *ciphertext = malloc(pt_len > 0 ? pt_len : 1);
    unsigned char tag[TAG_LEN];
    int ct_len = aes_gcm_encrypt(file_key, nonce, NONCE_LEN,
                                 (const unsigned char *)basename, basename_len,
                                 plaintext, pt_len,
                                 ciphertext, tag, TAG_LEN);
    if (ct_len < 0) { fprintf(stderr, "encrypt failed\n"); return 1; }
    memset(file_key, 0, FILE_KEY_LEN);

    /* Wire framing: [4 fname_len][fname][12 nonce][4 ct_len][ct][16 tag] */
    uint32_t nlen_net = htonl((uint32_t)basename_len);
    uint32_t clen_net = htonl((uint32_t)ct_len);
    send_all(sock, &nlen_net, 4);
    send_all(sock, basename, basename_len);
    send_all(sock, nonce, NONCE_LEN);
    send_all(sock, &clen_net, 4);
    send_all(sock, ciphertext, ct_len);
    send_all(sock, tag, TAG_LEN);

    printf("[CLIENT] Sent \"%s\": %zu B plaintext, %d B ciphertext, %d B tag\n",
           basename, pt_len, ct_len, TAG_LEN);

    free(plaintext); free(ciphertext);
    OM_uint32 min_s;
    gss_delete_sec_context(&min_s, &ctx, GSS_C_NO_BUFFER);
    close(sock);
    return 0;
}
