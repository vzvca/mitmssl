#include "mitmssl.h"
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <time.h>
#ifdef __linux__
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
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
    struct addrinfo hints, *res = NULL, *ai;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    char portstr[8];
    snprintf(portstr, sizeof(portstr), "%u", port);

    if (getaddrinfo(host, portstr, &hints, &res) != 0)
        return -1;

    int fd = -1;
    for (ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0)
            break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
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

static const unsigned char ALPN_HTTP11[] = "\x08" "http/1.1";

int alpn_select_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                  const unsigned char *in, unsigned int inlen, void *arg)
{
    (void)ssl; (void)arg;
    if (SSL_select_next_proto((unsigned char **)out, outlen,
                              in, inlen, ALPN_HTTP11,
                              sizeof(ALPN_HTTP11) - 1)
            == OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_OK;
    return SSL_TLSEXT_ERR_NOACK;
}


/* Choreography context, attached to the client SSL via ex_data.
 * The client_hello callback runs on the first ClientHello: at that
 * point we have the SNI, we connect upstream, clone its certificate,
 * and attach it before the handshake continues. */
struct chg_ctx {
    char host[256];
    uint16_t port;
    int64_t id;
    struct conn_log *lg;
    int fd;
};

static int g_chg_idx = -1;

static void chg_idx_init(void)
{
    if (g_chg_idx < 0)
        g_chg_idx = CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_SSL, 0,
                                             NULL, NULL, NULL, NULL);
}

int client_hello_cb(SSL *ssl, int *al, void *arg)
{
    (void)al; (void)arg;
    struct chg_ctx *cc = SSL_get_ex_data(ssl, g_chg_idx);
    if (!cc) return SSL_CLIENT_HELLO_ERROR;

    /* client_hello_cb runs before OpenSSL parses extensions: extract
     * the SNI from the raw ClientHello ourselves. */
    const unsigned char *sni_buf = NULL;
    size_t sni_len = 0;
    char sni_buf_c[256] = {0};
    const char *sni = NULL;
    if (SSL_client_hello_get0_ext(ssl, TLSEXT_NAMETYPE_host_name,
                                  &sni_buf, &sni_len) && sni_buf && sni_len > 5) {
        /* server_name extension: 2-byte list len, 1-byte type (0=hostname),
         * 2-byte len, then the name */
        size_t name_len = (size_t)(sni_buf[3] << 8) | sni_buf[4];
        if (name_len > 0 && name_len < sizeof(sni_buf_c) && name_len <= sni_len - 5) {
            memcpy(sni_buf_c, sni_buf + 5, name_len);
            sni_buf_c[name_len] = 0;
            sni = sni_buf_c;
        }
    }
    const char *upstream_host = sni ? sni : cc->host;

    output_step(cc->id, "client hello: sni=%s", sni ? sni : "(none)");
    output_step(cc->id, "connecting to upstream %s:%u", upstream_host, cc->port);

    int rfd = connect_remote(upstream_host, cc->port);
    if (rfd < 0) {
        output_step(cc->id, "upstream connect failed: %s:%u",
                     upstream_host, cc->port);
        *al = SSL_AD_INTERNAL_ERROR;
        return SSL_CLIENT_HELLO_ERROR;
    }
    output_step(cc->id, "upstream connected %s:%u", upstream_host, cc->port);

    SSL *srv = SSL_new(g_server_ctx);
    if (!srv) { close(rfd); *al = SSL_AD_INTERNAL_ERROR; return SSL_CLIENT_HELLO_ERROR; }
    SSL_set_fd(srv, rfd);
    SSL_set_connect_state(srv);
    if (sni)
        SSL_set_tlsext_host_name(srv, sni);
    SSL_set_alpn_protos(srv, ALPN_HTTP11, sizeof(ALPN_HTTP11) - 1);

    if (SSL_connect(srv) <= 0) {
        output_step(cc->id, "upstream TLS handshake failed");
        fprintf(stderr, APP_NAME ": upstream TLS handshake failed for %s:%u\n",
                upstream_host, cc->port);
        ERR_print_errors_fp(stderr);
        SSL_free(srv);
        close(rfd);
        *al = SSL_AD_INTERNAL_ERROR;
        return SSL_CLIENT_HELLO_ERROR;
    }

    const SSL_CIPHER *uc = SSL_get_current_cipher(srv);
    output_step(cc->id, "upstream TLS ok: %s cipher=%s",
                SSL_get_version(srv), uc ? SSL_CIPHER_get_name(uc) : "?");

    X509 *peer = SSL_get1_peer_certificate(srv);
    X509 *served = NULL;
    if (peer) {
        char subj[256] = "unknown";
        served = clone_cert(peer, subj, sizeof(subj));
        if (served)
            output_step(cc->id, "cloned upstream cert: subject=%s", subj);
        X509_free(peer);
    }
    if (!served) {
        served = forge_cert(upstream_host);
        if (served)
            output_step(cc->id, "fallback forged cert for %s", upstream_host);
    }
    if (!served) {
        SSL_free(srv);
        close(rfd);
        *al = SSL_AD_INTERNAL_ERROR;
        return SSL_CLIENT_HELLO_ERROR;
    }

    SSL_set_ex_data(ssl, g_chg_idx, cc);
    cc->fd = rfd;

    /* Stash the upstream SSL on a second ex_data slot */
    SSL_set_ex_data(ssl, g_chg_idx + 1000, srv);

    SSL_use_certificate(ssl, served);
    /* g_leaf_key is shared across threads: bump its refcount so that
     * SSL_free on any single connection cannot free it under the feet
     * of the others (race observed under load: alert 42). */
    if (EVP_PKEY_up_ref(g_leaf_key) <= 0) {
        X509_free(served);
        SSL_free(srv);
        close(rfd);
        *al = SSL_AD_INTERNAL_ERROR;
        return SSL_CLIENT_HELLO_ERROR;
    }
    SSL_use_PrivateKey(ssl, g_leaf_key);
    return SSL_CLIENT_HELLO_SUCCESS;
}

static SSL *get_upstream_ssl(SSL *cli)
{
    return SSL_get_ex_data(cli, g_chg_idx + 1000);
}

static int do_direct_tls(struct thread_arg *ta, char *host, uint16_t port)
{
    chg_idx_init();

    int64_t id = output_open_flow(host, port, NULL, 0);
    struct conn_log *lg = calloc(1, sizeof(*lg));
    if (!lg) return -1;
    lg->id = id;

    struct chg_ctx *cc = calloc(1, sizeof(*cc));
    if (!cc) { log_free(lg); close(ta->fd); free(ta); return -1; }
    snprintf(cc->host, sizeof(cc->host), "%s", host);
    cc->port = port;
    cc->id = id;
    cc->lg = lg;
    cc->fd = -1;

    SSL *cli = SSL_new(g_client_ctx);
    if (!cli) {
        free(cc);
        log_free(lg);
        close(ta->fd);
        free(ta);
        return -1;
    }
    SSL_set_fd(cli, ta->fd);
    SSL_set_ex_data(cli, g_chg_idx, cc);
    SSL_set_accept_state(cli);

    if (SSL_accept(cli) <= 0) {
        output_step(id, "client TLS handshake failed");
        ERR_print_errors_fp(stderr);
        SSL *dead = get_upstream_ssl(cli);
        if (dead) { SSL_free(dead); }
        if (cc->fd >= 0) close(cc->fd);
        SSL_free(cli);
        free(cc);
        log_free(lg);
        close(ta->fd);
        free(ta);
        return -1;
    }

    SSL *srv = get_upstream_ssl(cli);
    if (!srv) {
        SSL_free(cli);
        free(cc);
        log_free(lg);
        close(ta->fd);
        free(ta);
        return -1;
    }
    int rfd = cc->fd;

    const unsigned char *alpn = NULL;
    unsigned int alpn_len = 0;
    SSL_get0_alpn_selected(cli, &alpn, &alpn_len);
    const SSL_CIPHER *cc2 = SSL_get_current_cipher(cli);
    output_step(id, "client TLS ok: %s cipher=%s alpn=%.*s",
                SSL_get_version(cli),
                cc2 ? SSL_CIPHER_get_name(cc2) : "?",
                (int)alpn_len, (const char *)alpn);

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
    free(cc);
    close(rfd);
    close(ta->fd);
    free(ta);
    return 0;
}


static int get_original_dst(int fd, char *host, size_t hostcap, uint16_t *port)
{
    struct sockaddr_in6 sa6;
    socklen_t len6 = sizeof(sa6);
    if (getsockopt(fd, SOL_IPV6, IP6T_SO_ORIGINAL_DST, &sa6, &len6) == 0
        && sa6.sin6_family == AF_INET6) {
        if (!inet_ntop(AF_INET6, &sa6.sin6_addr, host, (socklen_t)hostcap))
            return -1;
        *port = ntohs(sa6.sin6_port);
        return 0;
    }

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
    char host[INET6_ADDRSTRLEN];
    uint16_t port;
    if (get_original_dst(ta->fd, host, sizeof(host), &port) != 0) {
        fprintf(stderr,
                APP_NAME ": cannot recover original destination "
                         "(not NATed, or unsupported family)\n");
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
