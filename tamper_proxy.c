#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>

#define TAMPER_OFFSET 3000  /* bytes, past typical GSS handshake */

struct relay_args { int src; int dst; int tamper; };

static void *relay(void *v) {
    struct relay_args *a = v;
    unsigned char buf[65536];
    int tampered = 0;
    size_t cum = 0;
    ssize_t n;

    while ((n = recv(a->src, buf, sizeof(buf), 0)) > 0) {
        if (a->tamper && !tampered && cum + (size_t)n > TAMPER_OFFSET) {
            size_t off = (cum < TAMPER_OFFSET) ? (TAMPER_OFFSET - cum) : 0;
            if (off < (size_t)n) {
                unsigned char orig = buf[off];
                buf[off] ^= 0xFF;
                fprintf(stderr,
                        "[PROXY] Flipped byte at cum offset %zu: 0x%02x -> 0x%02x\n",
                        cum + off, orig, buf[off]);
                tampered = 1;
            }
        }
        cum += (size_t)n;
        if (send(a->dst, buf, (size_t)n, 0) < 0) break;
    }
    shutdown(a->dst, SHUT_WR);
    free(a);
    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr,
                "Usage: %s <listen_port> <server_host> <server_port>\n", argv[0]);
        return 1;
    }
    int lport = atoi(argv[1]);
    const char *shost = argv[2];
    int sport = atoi(argv[3]);

    int listener = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in la = { .sin_family = AF_INET,
                              .sin_port   = htons(lport),
                              .sin_addr.s_addr = INADDR_ANY };
    bind(listener, (struct sockaddr *)&la, sizeof(la));
    listen(listener, 5);
    printf("[PROXY] Listening on %d, forwarding to %s:%d "
           "(flipping 1 byte in C>S at offset %d)\n",
           lport, shost, sport, TAMPER_OFFSET);

    while (1) {
        int c = accept(listener, NULL, NULL);
        if (c < 0) continue;

        struct hostent *he = gethostbyname(shost);
        if (!he) { close(c); continue; }
        int s = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in sa = { .sin_family = AF_INET,
                                  .sin_port   = htons(sport) };
        memcpy(&sa.sin_addr, he->h_addr_list[0], he->h_length);
        if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
            perror("connect upstream"); close(c); close(s); continue;
        }

        struct relay_args *a1 = malloc(sizeof(*a1));
        struct relay_args *a2 = malloc(sizeof(*a2));
        *a1 = (struct relay_args){ .src = c, .dst = s, .tamper = 1 };
        *a2 = (struct relay_args){ .src = s, .dst = c, .tamper = 0 };
        pthread_t t1, t2;
        pthread_create(&t1, NULL, relay, a1); pthread_detach(t1);
        pthread_create(&t2, NULL, relay, a2); pthread_detach(t2);
    }
}
