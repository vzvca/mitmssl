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

    if (g_mime) {
        lg->insp_c2s = inspect_new();
        lg->insp_s2c = inspect_new();
    }

    if (g_exec_cmd) {
        char hostonly[256];
        snprintf(hostonly, sizeof(hostonly), "%.*s",
                 (int)(sizeof(hostonly)-1), host);
        char *colon = strchr(hostonly, ':');
        if (colon) *colon = 0;
        char *end = NULL;
        unsigned long port = strtoul(peer ? strchr(peer, ':') + 1 : "0",
                                    &end, 10);
        lg->fe = exec_open(hostonly, (uint16_t)port);
    }

    return lg;
}

void log_write(struct conn_log *lg, int to_server, const void *buf, size_t n)
{
    if (!lg) return;
    FILE *f = to_server ? lg->c2s : lg->s2c;
    struct inspect_ctx *ic = to_server ? lg->insp_c2s : lg->insp_s2c;

    if (ic)
        inspect_write(ic, f, buf, n);
    else
        fwrite(buf, 1, n, f);
    fflush(f);

    if (lg->fe)
        exec_write(lg->fe, to_server, buf, n);
}

void log_close(struct conn_log *lg)
{
    if (!lg) return;
    if (lg->fe) exec_close(lg->fe);
    if (lg->insp_c2s) inspect_free(lg->insp_c2s);
    if (lg->insp_s2c) inspect_free(lg->insp_s2c);
    if (lg->c2s) fclose(lg->c2s);
    if (lg->s2c) fclose(lg->s2c);
    free(lg);
}
