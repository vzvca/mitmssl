#ifndef MITMSSL_H
#define MITMSSL_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/select.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define APP_NAME      "mitmssl"
#define DEFAULT_PORT  8080

struct inspect_ctx;

struct conn_log {
    int64_t id;
    struct inspect_ctx *insp_c2s;
    struct inspect_ctx *insp_s2c;
};

void log_free(struct conn_log *lg);

extern EVP_PKEY *g_ca_key;
extern X509      *g_ca_cert;
extern EVP_PKEY  *g_leaf_key;
extern SSL_CTX   *g_client_ctx;
extern SSL_CTX   *g_server_ctx;
extern int g_insecure;
extern int g_transparent;
extern int g_mime;
extern int g_binary;
extern const char *g_ca_path;

int  ca_load(const char *keypath, const char *certpath);
int  ca_generate(const char *keypath, const char *certpath);

X509 *forge_cert(const char *host);

struct inspect_ctx *inspect_new(void);
void inspect_free(struct inspect_ctx *ic);
void inspect_write(struct inspect_ctx *ic, FILE *f,
                   const unsigned char *buf, size_t n);

int64_t output_open_flow(const char *host, uint16_t port,
                         const char *alpn, size_t alpn_len);
void output_data(int64_t id, int to_server,
                 const void *buf, size_t n, struct inspect_ctx *ic);
void output_eof(int64_t id);

int  server_name_callback(SSL *ssl, int *al, void *arg);
int  alpn_select_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                   const unsigned char *in, unsigned int inlen, void *arg);
void stop_all(int sig);
int  is_stopping(void);

struct thread_arg {
    int fd;
};

void *conn_thread(void *arg);

#endif
