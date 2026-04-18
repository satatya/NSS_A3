#ifndef NETUTIL_H
#define NETUTIL_H

#include <stddef.h>

int send_all(int sock, const void *buf, size_t len);
int recv_all(int sock, void *buf, size_t len);
int send_token(int sock, const void *token, size_t len);
int recv_token(int sock, void **token, size_t *len);

#endif
