#include "netutil.h"
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <unistd.h>

int send_all(int sock, const void *buf, size_t len) {
    const char *p = buf;
    size_t total = 0;
    while (total < len) {
        ssize_t n = send(sock, p + total, len - total, 0);
        if (n <= 0) return -1;
        total += (size_t)n;
    }
    return 0;
}

int recv_all(int sock, void *buf, size_t len) {
    char *p = buf;
    size_t total = 0;
    while (total < len) {
        ssize_t n = recv(sock, p + total, len - total, 0);
        if (n <= 0) return -1;
        total += (size_t)n;
    }
    return 0;
}

int send_token(int sock, const void *token, size_t len) {
    uint32_t net_len = htonl((uint32_t)len);
    if (send_all(sock, &net_len, 4) < 0) return -1;
    if (len > 0 && send_all(sock, token, len) < 0) return -1;
    return 0;
}

int recv_token(int sock, void **token, size_t *len) {
    uint32_t net_len;
    if (recv_all(sock, &net_len, 4) < 0) return -1;
    *len = ntohl(net_len);
    if (*len == 0) { *token = NULL; return 0; }
    *token = malloc(*len);
    if (!*token) return -1;
    if (recv_all(sock, *token, *len) < 0) { free(*token); return -1; }
    return 0;
}
