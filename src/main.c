#include "mitmssl.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <signal.h>
#include <getopt.h>

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [options]\n"
        "  -l PORT     listen port (default 8080)\n"
        "  -k          do not verify upstream server certificates\n"
        "  -t          transparent mode (SO_ORIGINAL_DST, no CONNECT)\n"
        "  -m          MIME-aware rendering: hexdump binary HTTP bodies\n"
        "  -b          binary output framing on stdout: 12-byte header\n"
        "              {int32 op; int32 sz; int32 id;} + sz bytes;\n"
        "              op: 1=OPEN, 2=IN(c2s), 3=OUT(s2c), 4=EOF\n"
        "  -C KEY,CERT  CA key and cert paths; generated if absent\n"
        "  -h          help\n"
        "\n"
        "  Decoded traffic goes to stdout. Text framing (default):\n"
        "    # <id> OPEN <host>:<port>\n"
        "    <id> >> <n>  followed by n raw bytes (client to server)\n"
        "    <id> << <n>  followed by n raw bytes (server to client)\n"
        "    <id> ## EOF\n"
        "  Use shell pipes to process the stream, e.g.:\n"
        "    ./mitmssl | tee capture.txt\n"
        "  With -m, IN/OUT frames are rendered (text kept, binary\n"
        "  hexdumped) instead of raw bytes.\n",
        prog);
    exit(1);
}

int main(int argc, char **argv)
{
    int port = DEFAULT_PORT;
    const char *ca_key = "ca.key";
    const char *ca_cert = "ca.crt";

    int opt;
    while ((opt = getopt(argc, argv, "l:ktmbC:h")) != -1) {
        switch (opt) {
        case 'l': port = atoi(optarg); break;
        case 'k': g_insecure = 1; break;
        case 't': g_transparent = 1; break;
        case 'm': g_mime = 1; break;
        case 'b': g_binary = 1; break;
        case 'C': {
            char *comma = strchr(optarg, ',');
            if (!comma) usage(argv[0]);
            *comma = 0;
            ca_key = optarg;
            ca_cert = comma + 1;
            break;
        }
        case 'h':
        default:
            usage(argv[0]);
        }
    }

    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT,  stop_all);
    signal(SIGTERM, stop_all);

    if (ca_load(ca_key, ca_cert) != 0) {
        fprintf(stderr, APP_NAME ": generating new CA (%s, %s)\n",
                ca_key, ca_cert);
        if (ca_generate(ca_key, ca_cert) != 0) {
            fprintf(stderr, APP_NAME ": CA generation failed\n");
            return 1;
        }
    }

    g_leaf_key = EVP_RSA_gen(2048);
    if (!g_leaf_key) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    g_client_ctx = SSL_CTX_new(TLS_server_method());
    if (!g_client_ctx) {
        ERR_print_errors_fp(stderr);
        return 1;
    }
    SSL_CTX_set_min_proto_version(g_client_ctx, TLS1_2_VERSION);
    SSL_CTX_set_tlsext_servername_callback(g_client_ctx,
                                            server_name_callback);
    SSL_CTX_set_alpn_select_cb(g_client_ctx, alpn_select_cb, NULL);
    SSL_CTX_use_PrivateKey(g_client_ctx, g_leaf_key);

    g_server_ctx = SSL_CTX_new(TLS_client_method());
    if (!g_server_ctx) {
        ERR_print_errors_fp(stderr);
        return 1;
    }
    SSL_CTX_set_min_proto_version(g_server_ctx, TLS1_2_VERSION);
    if (!g_insecure) {
        SSL_CTX_set_default_verify_paths(g_server_ctx);
        SSL_CTX_set_verify(g_server_ctx, SSL_VERIFY_PEER, NULL);
    }

    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) { perror("socket"); return 1; }
    int one = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((uint16_t)port);

    if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("bind");
        return 1;
    }
    if (listen(lfd, 64) != 0) {
        perror("listen");
        return 1;
    }

    fprintf(stderr, APP_NAME ": listening on 127.0.0.1:%d\n", port);

    while (!is_stopping()) {
        int cfd = accept(lfd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            break;
        }
        struct thread_arg *ta = malloc(sizeof(*ta));
        if (!ta) { close(cfd); continue; }
        ta->fd = cfd;
        pthread_t th;
        if (pthread_create(&th, NULL, conn_thread, ta) != 0) {
            close(cfd);
            free(ta);
            continue;
        }
        pthread_detach(th);
    }

    close(lfd);
    return 0;
}
