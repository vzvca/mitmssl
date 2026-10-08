#include "mitmssl.h"
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <time.h>
#ifdef __linux__
#include <linux/netfilter_ipv4.h>
#endif

#define BUF_SIZE 16384

static volatile sig_atomic_t g_stop = 0;

void stop_all(int sig)
{
    (void)sig;
    g_stop = 1;
}

int is_stopping(void)
{
    return g_stop;
}

void log_free(struct conn_log *lg)
{
    if (!lg) return;
    if (lg->insp_c2s) inspect_free(lg->insp_c2s);
    if (lg->insp_s2c) inspect_free(lg->insp_s2c);
    free(lg);
}

static int connect_remote(const char *host, uint16_t port)
{
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &sa.sin_addr) != 1) return -1;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int send_all(int fd, const void *buf, size_t n)
{
    const char *p = buf;
    while (n > 0) {
        ssize_t w = send(fd, p, n, 0);
        if (w <= 0) return -1;
        p += w;
        n -= (size_t)w;
    }
    return 0;
}

static int read_line_crlf(int fd, char *buf, size_t cap, size_t *out_len)
{
    size_t len = 0;
    while (len + 1 < cap) {
        char c;
        ssize_t r = recv(fd, &c, 1, 0);
        if (r <= 0) return -1;
        if (c == '\n') {
            if (len > 0 && buf[len-1] == '\r') len--;
            buf[len] = 0;
            *out_len = len;
            return 0;
        }
        buf[len++] = c;
    }
    return -1;
}

static int g_host_idx = -1;

static void host_idx_init(void)
{
    if (g_host_idx < 0)
        g_host_idx = CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_SSL, 0,
                                             NULL, NULL, NULL, NULL);
}

int server_name_callback(SSL *ssl, int *al, void *arg)
{
    (void)al; (void)arg;
    const char *host = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (!host && g_host_idx >= 0)
        host = SSL_get_ex_data(ssl, g_host_idx);
    if (!host)
        host = "unknown.local";
    X509 *cert = forge_cert(host);
    if (!cert) return SSL_TLSEXT_ERR_ALERT_FATAL;
    SSL_use_certificate(ssl, cert);
    SSL_use_PrivateKey(ssl, g_leaf_key);
    return SSL_TLSEXT_ERR_OK;
}

static int do_direct_tls(struct thread_arg *ta, char *host, uint16_t port)
{
    host_idx_init();
    SSL *cli = SSL_new(g_client_ctx);
    if (!cli) return -1;
    SSL_set_fd(cli, ta->fd);
    SSL_set_ex_data(cli, g_host_idx, (void *)host);
    SSL_set_accept_state(cli);
    if (SSL_accept(cli) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(cli);
        return -1;
    }

    const char *sni = SSL_get_servername(cli, TLSEXT_NAMETYPE_host_name);
    if (!sni) sni = host;

    int rfd = connect_remote(host, port);
    if (rfd < 0) {
        SSL_free(cli);
        return -1;
    }

    SSL *srv = SSL_new(g_server_ctx);
    SSL_set_fd(srv, rfd);
    SSL_set_connect_state(srv);
    SSL_set_tlsext_host_name(srv, sni);
    if (SSL_connect(srv) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(srv);
        SSL_free(cli);
        close(rfd);
        return -1;
    }

    struct conn_log *lg = calloc(1, sizeof(*lg));
    if (!lg) return -1;
    lg->id = output_open_flow(sni, port);
    if (g_mime) {
        lg->insp_c2s = inspect_new();
        lg->insp_s2c = inspect_new();
        if (!lg->insp_c2s || !lg->insp_s2c) {
            log_free(lg);
            return -1;
        }
    }

    fd_set rfds;
    char buf[BUF_SIZE];
    int cfd = SSL_get_fd(cli);
    int maxfd = (cfd > rfd ? cfd : rfd) + 1;

    while (!is_stopping()) {
        FD_ZERO(&rfds);
        FD_SET(cfd, &rfds);
        FD_SET(rfd, &rfds);
        if (select(maxfd, &rfds, NULL, NULL, NULL) < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (FD_ISSET(cfd, &rfds)) {
            int n = SSL_read(cli, buf, sizeof(buf));
            if (n <= 0) break;
            output_data(lg->id, 1, buf, (size_t)n, lg->insp_c2s);
            if (SSL_write(srv, buf, (size_t)n) <= 0) break;
        }
        if (FD_ISSET(rfd, &rfds)) {
            int n = SSL_read(srv, buf, sizeof(buf));
            if (n <= 0) break;
            output_data(lg->id, 0, buf, (size_t)n, lg->insp_s2c);
            if (SSL_write(cli, buf, (size_t)n) <= 0) break;
        }
    }

    output_eof(lg->id);
    log_free(lg);
    SSL_shutdown(srv);
    SSL_shutdown(cli);
    SSL_free(srv);
    SSL_free(cli);
    close(rfd);
    close(ta->fd);
    free(ta);
    return 0;
}

static int get_original_dst(int fd, char *host, size_t hostcap, uint16_t *port)
{
    struct sockaddr_in sa;
    socklen_t len = sizeof(sa);
    if (getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, &sa, &len) != 0)
        return -1;
    if (!inet_ntop(AF_INET, &sa.sin_addr, host, (socklen_t)hostcap))
        return -1;
    *port = ntohs(sa.sin_port);
    return 0;
}

static int do_transparent(struct thread_arg *ta)
{
    char host[INET_ADDRSTRLEN];
    uint16_t port;
    if (get_original_dst(ta->fd, host, sizeof(host), &port) != 0) {
        close(ta->fd);
        free(ta);
        return -1;
    }
    return do_direct_tls(ta, host, port);
}

static int do_connect_proxy(struct thread_arg *ta)
{
    char line[1024];
    size_t len;
    char host[256] = {0};
    uint16_t port = 443;

    if (read_line_crlf(ta->fd, line, sizeof(line), &len) < 0) return -1;

    if (strncasecmp(line, "CONNECT ", 8) != 0) {
        send_all(ta->fd, "HTTP/1.1 405 Method Not Allowed\r\n\r\n", 34);
        return -1;
    }

    char *p = line + 8;
    char *colon = strchr(p, ':');
    if (colon) {
        size_t hlen = (size_t)(colon - p);
        if (hlen >= sizeof(host)) hlen = sizeof(host) - 1;
        memcpy(host, p, hlen);
        host[hlen] = 0;
        port = (uint16_t)strtoul(colon + 1, NULL, 10);
    } else {
        snprintf(host, sizeof(host), "%.*s", (int)(sizeof(host)-1), p);
        port = 443;
    }

    while (read_line_crlf(ta->fd, line, sizeof(line), &len) == 0) {
        if (len == 0) break;
    }

    send_all(ta->fd, "HTTP/1.1 200 Connection Established\r\n\r\n", 39);

    return do_direct_tls(ta, host, port);
}

void *conn_thread(void *arg)
{
    struct thread_arg *ta = arg;

    if (g_transparent) {
        do_transparent(ta);
        return NULL;
    }

    char first[8];
    ssize_t r = recv(ta->fd, first, 1, MSG_PEEK);
    if (r != 1) {
        close(ta->fd);
        free(ta);
        return NULL;
    }

    int is_tls = (first[0] == 0x16);

    if (is_tls) {
        char host[256] = "unknown.local";
        do_direct_tls(ta, host, 443);
    } else {
        do_connect_proxy(ta);
    }
    return NULL;
}
