#include "mitmssl.h"
#include <sys/wait.h>
#include <fcntl.h>

struct flow_exec {
    pid_t pid;
    int fd;
};

static char *build_cmd(const char *tmpl, const char *host, uint16_t port)
{
    size_t cap = strlen(tmpl) + strlen(host) + 32;
    char *cmd = malloc(cap);
    if (!cmd) return NULL;
    char *o = cmd;
    for (const char *p = tmpl; *p; p++) {
        if (*p == '%' && p[1] == 'h') {
            o += snprintf(o, cap - (size_t)(o - cmd), "%s", host);
            p++;
        } else if (*p == '%' && p[1] == 'p') {
            o += snprintf(o, cap - (size_t)(o - cmd), "%u", port);
            p++;
        } else if (*p == '%' && p[1] == '%') {
            *o++ = '%';
            p++;
        } else {
            *o++ = *p;
        }
    }
    *o = 0;
    return cmd;
}

struct flow_exec *exec_open(const char *host, uint16_t port)
{
    if (!g_exec_cmd) return NULL;

    char *cmd = build_cmd(g_exec_cmd, host, port);
    if (!cmd) return NULL;

    int pfd[2];
    if (pipe(pfd) != 0) {
        free(cmd);
        return NULL;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(pfd[0]);
        close(pfd[1]);
        free(cmd);
        return NULL;
    }
    if (pid == 0) {
        close(pfd[1]);
        if (pfd[0] != STDIN_FILENO) {
            dup2(pfd[0], STDIN_FILENO);
            close(pfd[0]);
        }
        char pbuf[16];
        snprintf(pbuf, sizeof(pbuf), "%u", port);
        setenv("MITMSSL_HOST", host, 1);
        setenv("MITMSSL_PORT", pbuf, 1);
        execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
        _exit(127);
    }

    close(pfd[0]);
    free(cmd);

    struct flow_exec *fe = malloc(sizeof(*fe));
    if (!fe) {
        close(pfd[1]);
        return NULL;
    }
    fe->pid = pid;
    fe->fd = pfd[1];
    int flags = fcntl(fe->fd, F_GETFL, 0);
    fcntl(fe->fd, F_SETFL, flags | O_NONBLOCK);
    return fe;
}

static int write_full(int fd, const void *buf, size_t n)
{
    const char *p = buf;
    while (n > 0) {
        ssize_t w = write(fd, p, n);
        if (w < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN) { usleep(1000); continue; }
            return -1;
        }
        p += w;
        n -= (size_t)w;
    }
    return 0;
}

void exec_write(struct flow_exec *fe, int to_server,
                const void *buf, size_t n)
{
    if (!fe) return;
    char hdr[64];
    int len = snprintf(hdr, sizeof(hdr), "%s %zu\n",
                       to_server ? ">>" : "<<", n);
    if (write_full(fe->fd, hdr, (size_t)len) < 0) return;
    write_full(fe->fd, buf, n);
}

void exec_close(struct flow_exec *fe)
{
    if (!fe) return;
    write_full(fe->fd, "## EOF\n", 7);
    close(fe->fd);
    waitpid(fe->pid, NULL, WNOHANG);
    free(fe);
}
