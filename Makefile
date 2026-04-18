# Makefile - Secure File Copy (SFC) on FreeBSD

CC = cc

# ---- Profile A: FreeBSD <= 14  (MIT Kerberos from `pkg install krb5`) ----
CFLAGS   = -Wall -Wextra -O2 -I/usr/local/include
LDFLAGS  = -L/usr/local/lib -Wl,-rpath,/usr/local/lib
GSS_LIBS = -lgssapi_krb5 -lkrb5 -lk5crypto -lcom_err
SSL_LIBS = -lcrypto

# ---- Profile B: FreeBSD >= 15  (MIT Kerberos in base) ----
# CFLAGS   = -Wall -Wextra -O2
# LDFLAGS  =
# GSS_LIBS = -lgssapi_krb5 -lkrb5 -lk5crypto -lcom_err
# SSL_LIBS = -lcrypto

COMMON_OBJ = netutil.o gss_util.o crypto_util.o

.PHONY: all clean
all: sfc-client sfc-server tamper_proxy

sfc-client: sfc_client.o $(COMMON_OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ $(GSS_LIBS) $(SSL_LIBS)

sfc-server: sfc_server.o $(COMMON_OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ $(GSS_LIBS) $(SSL_LIBS)

tamper_proxy: tamper_proxy.o
	$(CC) $(LDFLAGS) -o $@ $^ -pthread

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o sfc-client sfc-server tamper_proxy
