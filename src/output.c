#include "mitmssl.h"

#include <stdatomic.h>

enum {
    OP_OPEN = 1,
    OP_IN   = 2,
    OP_OUT  = 3,
    OP_EOF  = 4
};

static pthread_mutex_t g_out_mu = PTHREAD_MUTEX_INITIALIZER;
static atomic_llong g_flow_seq = 0;

int64_t output_open_flow(const char *host, uint16_t port,
                         const char *alpn, size_t alpn_len)
{
    int64_t id = atomic_fetch_add(&g_flow_seq, 1) + 1;

    pthread_mutex_lock(&g_out_mu);
    if (g_binary) {
        char data[300];
        int sz;
        if (alpn_len > 0)
            sz = snprintf(data, sizeof(data), "%s:%u alpn=%.*s",
                          host, port, (int)alpn_len, alpn);
        else
            sz = snprintf(data, sizeof(data), "%s:%u", host, port);
        int32_t hdr[3] = { OP_OPEN, sz, (int32_t)id };
        fwrite(hdr, sizeof(hdr), 1, stdout);
        fwrite(data, 1, (size_t)sz, stdout);
    } else {
        if (alpn_len > 0)
            printf("# %lld OPEN %s:%u alpn=%.*s\n",
                   (long long)id, host, port, (int)alpn_len, alpn);
        else
            printf("# %lld OPEN %s:%u\n", (long long)id, host, port);
    }
    fflush(stdout);
    pthread_mutex_unlock(&g_out_mu);
    return id;
}

static void bin_frame(int32_t op, int32_t id, const void *buf, size_t n)
{
    int32_t hdr[3] = { op, (int32_t)n, id };
    fwrite(hdr, sizeof(hdr), 1, stdout);
    if (n > 0) fwrite(buf, 1, n, stdout);
}

void output_data(int64_t id, int to_server,
                 const void *buf, size_t n, struct inspect_ctx *ic)
{
    pthread_mutex_lock(&g_out_mu);
    if (g_binary) {
        bin_frame(to_server ? OP_IN : OP_OUT, (int32_t)id, buf, n);
    } else if (ic) {
        char *rp = NULL;
        size_t rl = 0;
        FILE *mf = open_memstream(&rp, &rl);
        if (mf) {
            inspect_write(ic, mf, buf, n);
            fclose(mf);
            printf("%lld %s %zu\n", (long long)id,
                   to_server ? ">>" : "<<", rl);
            if (rl > 0) {
                fwrite(rp, 1, rl, stdout);
                if (rp[rl-1] != '\n') putchar('\n');
            }
            free(rp);
        }
    } else {
        printf("%lld %s %zu\n", (long long)id,
               to_server ? ">>" : "<<", n);
        if (n > 0) {
            fwrite(buf, 1, n, stdout);
            const unsigned char *b = buf;
            if (b[n-1] != '\n') putchar('\n');
        }
    }
    fflush(stdout);
    pthread_mutex_unlock(&g_out_mu);
}

void output_eof(int64_t id)
{
    pthread_mutex_lock(&g_out_mu);
    if (g_binary) {
        int32_t hdr[3] = { OP_EOF, 0, (int32_t)id };
        fwrite(hdr, sizeof(hdr), 1, stdout);
    } else {
        printf("%lld ## EOF\n", (long long)id);
    }
    fflush(stdout);
    pthread_mutex_unlock(&g_out_mu);
}
