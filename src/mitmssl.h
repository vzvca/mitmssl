#ifndef MITMSSL_H
#define MITMSSL_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define APP_NAME      "mitmssl"
#define DEFAULT_PORT  8080

struct conn_log {
    FILE *c2s;
    FILE *s2c;
};

extern EVP_PKEY *g_ca_key;
extern X509      *g_ca_cert;
extern EVP_PKEY  *g_leaf_key;
extern SSL_CTX   *g_client_ctx;
extern SSL_CTX   *g_server_ctx;
extern const char *g_logdir;
extern int g_insecure;
extern int g_transparent;

int  ca_load(const char *keypath, const char *certpath);
int  ca_generate(const char *keypath, const char *certpath);

X509 *forge_cert(const char *host);

struct conn_log *log_open(const char *host, const char *peer);
void log_write(struct conn_log *lg, int to_server, const void *buf, size_t n);
void log_close(struct conn_log *lg);

int  server_name_callback(SSL *ssl, int *al, void *arg);
void stop_all(int sig);
int  is_stopping(void);

struct thread_arg {
    int fd;
};

void *conn_thread(void *arg);

#endif
