#include "mitmssl.h"
#include <sys/stat.h>
#include <sys/types.h>

struct conn_log *log_open(const char *host, const char *peer)
{
    struct conn_log *lg = calloc(1, sizeof(*lg));
    if (!lg) return NULL;

    if (mkdir(g_logdir, 0755) != 0 && errno != EEXIST) {
        free(lg);
        return NULL;
    }

    char path[1024];
    snprintf(path, sizeof(path), "%s/%s.c2s", g_logdir, peer);
    lg->c2s = fopen(path, "ab");
    snprintf(path, sizeof(path), "%s/%s.s2c", g_logdir, peer);
    lg->s2c = fopen(path, "ab");
    if (!lg->c2s || !lg->s2c) {
        log_close(lg);
        return NULL;
    }
    (void)host;
    return lg;
}

void log_write(struct conn_log *lg, int to_server, const void *buf, size_t n)
{
    if (!lg) return;
    FILE *f = to_server ? lg->c2s : lg->s2c;
    fwrite(buf, 1, n, f);
    fflush(f);
}

void log_close(struct conn_log *lg)
{
    if (!lg) return;
    if (lg->c2s) fclose(lg->c2s);
    if (lg->s2c) fclose(lg->s2c);
    free(lg);
}
