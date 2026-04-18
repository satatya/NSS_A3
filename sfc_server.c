#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>

#include <gssapi/gssapi.h>
#include <gssapi/gssapi_generic.h>

#include "netutil.h"
#include "gss_util.h"
#include "crypto_util.h"

#define NONCE_LEN    12
#define TAG_LEN      16
#define FILE_KEY_LEN 32
#define OUTPUT_DIR   "./received"
#define MAX_FNAME     4096
#define MAX_CT   (1u << 30)

static int accept_server_ctx(int sock, gss_cred_id_t creds,
                             gss_ctx_id_t *out_ctx) {
    OM_uint32 maj = GSS_S_CONTINUE_NEEDED, min;
    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
    gss_name_t   client_name = GSS_C_NO_NAME;
    gss_buffer_desc recv_tok = GSS_C_EMPTY_BUFFER,
                    send_tok = GSS_C_EMPTY_BUFFER;

    while (maj == GSS_S_CONTINUE_NEEDED) {
        if (recv_token(sock, &recv_tok.value, &recv_tok.length) < 0)
            return -1;

        maj = gss_accept_sec_context(&min, &ctx, creds, &recv_tok,
                                     GSS_C_NO_CHANNEL_BINDINGS,
                                     &client_name, NULL, &send_tok,
                                     NULL, NULL, NULL);
        free(recv_tok.value); recv_tok.value = NULL;

        if (send_tok.length > 0) {
            send_token(sock, send_tok.value, send_tok.length);
            gss_release_buffer(&min, &send_tok);
        }
        if (GSS_ERROR(maj)) {
            display_gss_error("gss_accept_sec_context", maj, min);
            return -1;
        }
    }

    gss_buffer_desc nm = GSS_C_EMPTY_BUFFER;
    gss_display_name(&min, client_name, &nm, NULL);
    printf("[SERVER] Authenticated client: %.*s\n",
           (int)nm.length, (char *)nm.value);
    gss_release_buffer(&min, &nm);
    gss_release_name(&min, &client_name);

    *out_ctx = ctx;
    return 0;
}

static void handle_connection(int conn, gss_cred_id_t creds) {
    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
    if (accept_server_ctx(conn, creds, &ctx) < 0) return;

    unsigned char *session_key = NULL;
    size_t session_key_len = 0;
    if (extract_session_key(ctx, &session_key, &session_key_len) < 0) return;

    unsigned char file_key[FILE_KEY_LEN];
    if (derive_file_key(session_key, session_key_len,
                        file_key, FILE_KEY_LEN) < 0) {
        free(session_key); return;
    }
    memset(session_key, 0, session_key_len);
    free(session_key);

    /* Receive filename */
    uint32_t nlen_net;
    if (recv_all(conn, &nlen_net, 4) < 0) return;
    uint32_t nlen = ntohl(nlen_net);
    if (nlen == 0 || nlen > MAX_FNAME) {
        fprintf(stderr, "[SERVER] bad filename length\n"); return;
    }
    char *filename = malloc(nlen + 1);
    if (recv_all(conn, filename, nlen) < 0) { free(filename); return; }
    filename[nlen] = 0;

    /* Refuse any embedded path separators for safety */
    const char *s = strrchr(filename, '/');
    const char *safe = s ? s + 1 : filename;

    unsigned char nonce[NONCE_LEN];
    if (recv_all(conn, nonce, NONCE_LEN) < 0) { free(filename); return; }

    uint32_t clen_net;
    if (recv_all(conn, &clen_net, 4) < 0) { free(filename); return; }
    uint32_t ct_len = ntohl(clen_net);
    if (ct_len > MAX_CT) { free(filename); return; }

    unsigned char *ciphertext = malloc(ct_len);
    if (!ciphertext || recv_all(conn, ciphertext, ct_len) < 0) {
        free(ciphertext); free(filename); return;
    }
    unsigned char tag[TAG_LEN];
    if (recv_all(conn, tag, TAG_LEN) < 0) {
        free(ciphertext); free(filename); return;
    }

    printf("[SERVER] Received \"%s\": %u B ciphertext, verifying tag...\n",
           safe, ct_len);

    unsigned char *plaintext = malloc(ct_len ? ct_len : 1);
    int pt_len = aes_gcm_decrypt(file_key, nonce, NONCE_LEN,
                                 (const unsigned char *)filename, nlen,
                                 ciphertext, ct_len,
                                 tag, TAG_LEN, plaintext);
    memset(file_key, 0, FILE_KEY_LEN);

    if (pt_len == -2) {
        /* Tag verification failed: DO NOT write any output. */
        printf("[SERVER] TAG VERIFICATION FAILED - "
               "tampering detected. File REJECTED. No output written.\n");
    } else if (pt_len < 0) {
        printf("[SERVER] Decryption error. File REJECTED.\n");
    } else {
        mkdir(OUTPUT_DIR, 0755);
        char out_path[4200];
        snprintf(out_path, sizeof(out_path), "%s/%s", OUTPUT_DIR, safe);
        FILE *fp = fopen(out_path, "wb");
        if (fp) {
            fwrite(plaintext, 1, (size_t)pt_len, fp);
            fclose(fp);
            printf("[SERVER] Tag valid - wrote \"%s\" (%d B)\n",
                   out_path, pt_len);
        } else { perror("fopen output"); }
    }

    free(plaintext); free(ciphertext); free(filename);
    OM_uint32 min_s;
    gss_delete_sec_context(&min_s, &ctx, GSS_C_NO_BUFFER);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <port> [keytab_path]\n", argv[0]);
        return 1;
    }
    int port = atoi(argv[1]);
    const char *keytab = (argc > 2) ? argv[2] : "/etc/krb5.keytab";
    setenv("KRB5_KTNAME", keytab, 1);

    OM_uint32 maj, min;
    gss_cred_id_t creds = GSS_C_NO_CREDENTIAL;
    maj = gss_acquire_cred(&min, GSS_C_NO_NAME, GSS_C_INDEFINITE,
                           GSS_C_NO_OID_SET, GSS_C_ACCEPT,
                           &creds, NULL, NULL);
    if (GSS_ERROR(maj)) {
        display_gss_error("gss_acquire_cred", maj, min); return 1;
    }

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in addr = { .sin_family = AF_INET,
                                .sin_port   = htons(port),
                                .sin_addr.s_addr = INADDR_ANY };
    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); return 1;
    }
    listen(srv, 5);
    printf("[SERVER] Listening on port %d (keytab=%s)\n", port, keytab);

    while (1) {
        struct sockaddr_in cli; socklen_t cl = sizeof(cli);
        int conn = accept(srv, (struct sockaddr *)&cli, &cl);
        if (conn < 0) continue;
        printf("[SERVER] Connection from %s:%d\n",
               inet_ntoa(cli.sin_addr), ntohs(cli.sin_port));
        handle_connection(conn, creds);
        close(conn);
    }
    gss_release_cred(&min, &creds);
    close(srv);
    return 0;
}
