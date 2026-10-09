#include "mitmssl.h"
#include <ctype.h>

enum {
    S_START,        /* reading first line, deciding HTTP vs raw */
    S_HEADERS,      /* accumulating header block */
    S_BODY,         /* delimited by Content-Length */
    S_CHUNK_SIZE,
    S_CHUNK_CRLF,
    S_CHUNK_BODY,
    S_TRAILER,
    S_RAW           /* not HTTP (or body until close): heuristic dump */
};

struct inspect_ctx {
    int    state;
    char   block[16384];
    size_t blen;
    char   ct[128];
    long long body_left;
    size_t chunk_left;
    long long hex_off;
    int    is_req;
    int    text;
    int    status_no_body;
};

struct inspect_ctx *inspect_new(void)
{
    return calloc(1, sizeof(struct inspect_ctx));
}

void inspect_free(struct inspect_ctx *ic)
{
    free(ic);
}

static int is_printable(unsigned char c)
{
    return c == '\t' || c == '\n' || c == '\r' || (c >= 0x20 && c <= 0x7e);
}

static int printable_ratio(const unsigned char *p, size_t n)
{
    if (n == 0) return 1;
    size_t ok = 0;
    for (size_t i = 0; i < n; i++)
        if (is_printable(p[i])) ok++;
    return ok * 100 / n >= 95;
}

static void dump_hex(FILE *f, const unsigned char *p, size_t n, long long *off)
{
    for (size_t i = 0; i < n; i += 16) {
        fprintf(f, "%08llx  ", (unsigned long long)(*off + (long long)i));
        for (size_t j = 0; j < 16; j++) {
            if (i + j < n) fprintf(f, "%02x ", p[i + j]);
            else fputs("   ", f);
            if (j == 7) fputc(' ', f);
        }
        fputs(" |", f);
        for (size_t j = 0; j < 16 && i + j < n; j++)
            fputc(is_printable(p[i + j]) ? (char)p[i + j] : '.', f);
        fputs("|\n", f);
    }
    *off += (long long)n;
}

static void hdr_value(const char *block, size_t blen, const char *key,
                      char *out, size_t outcap)
{
    size_t klen = strlen(key);
    *out = 0;
    const char *p = block;
    const char *end = block + blen;
    while (p < end) {
        const char *eol = memchr(p, '\n', (size_t)(end - p));
        size_t linelen = eol ? (size_t)(eol - p) : (size_t)(end - p);
        if (linelen > klen && strncasecmp(p, key, klen) == 0) {
            const char *v = p + klen;
            while (v < p + linelen && (*v == ' ' || *v == '\t')) v++;
            size_t vlen = (size_t)(p + linelen - v);
            if (vlen >= outcap) vlen = outcap - 1;
            memcpy(out, v, vlen);
            out[vlen] = 0;
            return;
        }
        if (!eol) return;
        p = eol + 1;
    }
}

static int line_is_http(const char *line, size_t len, int *is_req)
{
    if (len >= 6 && strncmp(line, "HTTP/1", 6) == 0) {
        *is_req = 0;
        return 1;
    }
    if (len >= 9 && strncmp(line + len - 9, " HTTP/1.", 8) == 0) {
        *is_req = 1;
        return 1;
    }
    return 0;
}

static void parse_headers(struct inspect_ctx *ic, FILE *f)
{
    ic->block[ic->blen] = 0;

    ic->text = 1;
    char cl[32] = {0}, te[64] = {0};
    hdr_value(ic->block, ic->blen, "Content-Type:", ic->ct, sizeof(ic->ct));
    hdr_value(ic->block, ic->blen, "Content-Length:", cl, sizeof(cl));
    hdr_value(ic->block, ic->blen, "Transfer-Encoding:", te, sizeof(te));

    if (ic->ct[0]) {
        const char *bin[] = {"image/", "audio/", "video/",
                             "application/octet-stream",
                             "application/zip", "application/pdf",
                             "application/gzip", "application/x-protobuf", NULL};
        for (int i = 0; bin[i]; i++)
            if (strncasecmp(ic->ct, bin[i], strlen(bin[i])) == 0) {
                ic->text = 0;
                break;
            }
    }

    int chunked = te[0] && strcasestr(te, "chunked");
    long long content_len = cl[0] ? strtoll(cl, NULL, 10) : 0;

    fwrite(ic->block, 1, ic->blen, f);

    ic->status_no_body = 0;
    if (!ic->is_req) {
        int code = atoi(ic->block + 9);
        if ((code >= 100 && code < 200) || code == 204 || code == 304)
            ic->status_no_body = 1;
    }

    ic->blen = 0;
    ic->hex_off = 0;

    if (chunked) {
        ic->state = S_CHUNK_SIZE;
    } else if (ic->is_req) {
        ic->state = content_len > 0 ? S_BODY : S_START;
        ic->body_left = content_len;
    } else if (ic->status_no_body) {
        ic->state = S_START;
    } else if (content_len > 0) {
        ic->state = S_BODY;
        ic->body_left = content_len;
    } else {
        ic->state = S_RAW;
    }
    if (ic->state == S_BODY && !ic->text)
        fprintf(f, "\n== binary body, content-type: %s, %lld bytes ==\n",
                ic->ct[0] ? ic->ct : "unknown", ic->body_left);
}

void inspect_write(struct inspect_ctx *ic, FILE *f,
                   const unsigned char *buf, size_t n)
{
    if (!ic) { fwrite(buf, 1, n, f); return; }

    size_t i = 0;
    while (i < n) {
        switch (ic->state) {

        case S_START: {
            unsigned char c = buf[i++];
            if (ic->blen + 1 >= sizeof(ic->block)) {
                fwrite(ic->block, 1, ic->blen, f);
                ic->blen = 0;
                ic->state = S_RAW;
                break;
            }
            ic->block[ic->blen++] = (char)c;
            if (c == '\n') {
                ic->block[ic->blen] = 0;
                int is_req;
                if (line_is_http(ic->block, ic->blen, &is_req)) {
                    ic->is_req = is_req;
                    ic->state = S_HEADERS;
                } else {
                    fwrite(ic->block, 1, ic->blen, f);
                    ic->blen = 0;
                    ic->state = S_RAW;
                }
            }
            break;
        }

        case S_HEADERS: {
            size_t avail = n - i;
            size_t room = sizeof(ic->block) - 1 - ic->blen;
            size_t take = avail < room ? avail : room;
            memcpy(ic->block + ic->blen, buf + i, take);
            ic->blen += take;
            ic->block[ic->blen] = 0;
            char *hit = strstr(ic->block, "\r\n\r\n");
            if (hit) {
                size_t hlen = (size_t)(hit + 4 - ic->block);
                size_t from_input = hlen - (ic->blen - take);
                i += from_input;
                parse_headers(ic, f);
            } else {
                i += take;
                if (ic->blen + 1 >= sizeof(ic->block)) {
                    fwrite(ic->block, 1, ic->blen, f);
                    ic->blen = 0;
                    ic->state = S_RAW;
                }
            }
            break;
        }

        case S_BODY: {
            size_t avail = n - i;
            size_t take = (long long)avail < ic->body_left
                          ? avail : (size_t)ic->body_left;
            if (ic->text) fwrite(buf + i, 1, take, f);
            else dump_hex(f, buf + i, take, &ic->hex_off);
            i += take;
            ic->body_left -= (long long)take;
            if (ic->body_left == 0) ic->state = S_START;
            break;
        }

        case S_CHUNK_SIZE: {
            unsigned char c = buf[i++];
            if (ic->blen + 1 >= sizeof(ic->block)) {
                fwrite(ic->block, 1, ic->blen, f);
                ic->blen = 0;
                ic->state = S_RAW;
                break;
            }
            ic->block[ic->blen++] = (char)c;
            if (c == '\n') {
                ic->block[ic->blen] = 0;
                fwrite(ic->block, 1, ic->blen, f);
                ic->chunk_left = strtoul(ic->block, NULL, 16);
                ic->blen = 0;
                ic->hex_off = 0;
                if (ic->chunk_left == 0) ic->state = S_TRAILER;
                else {
                    ic->state = S_CHUNK_BODY;
                    if (!ic->text)
                        fprintf(f, "\n== binary chunk, content-type: %s, "
                                   "%zu bytes ==\n",
                                ic->ct[0] ? ic->ct : "unknown", ic->chunk_left);
                }
            }
            break;
        }

        case S_CHUNK_BODY: {
            size_t avail = n - i;
            size_t take = avail < ic->chunk_left ? avail : ic->chunk_left;
            if (ic->text) fwrite(buf + i, 1, take, f);
            else dump_hex(f, buf + i, take, &ic->hex_off);
            i += take;
            ic->chunk_left -= take;
            if (ic->chunk_left == 0) ic->state = S_CHUNK_CRLF;
            break;
        }

        case S_CHUNK_CRLF: {
            size_t avail = n - i;
            size_t take = avail < 2 ? avail : 2;
            i += take;
            if (take == 2) ic->state = S_CHUNK_SIZE;
            break;
        }

        case S_TRAILER: {
            unsigned char c = buf[i++];
            if (ic->blen + 1 >= sizeof(ic->block)) {
                fwrite(ic->block, 1, ic->blen, f);
                ic->blen = 0;
            }
            ic->block[ic->blen++] = (char)c;
            if (c == '\n') {
                ic->block[ic->blen] = 0;
                fwrite(ic->block, 1, ic->blen, f);
                if (ic->blen <= 2) {
                    ic->blen = 0;
                    ic->state = S_START;
                } else {
                    ic->blen = 0;
                }
            }
            break;
        }

        case S_RAW: {
            size_t avail = n - i;
            if (printable_ratio(buf + i, avail)) {
                fwrite(buf + i, 1, avail, f);
            } else {
                fprintf(f, "\n== binary data, %zu bytes ==\n", avail);
                dump_hex(f, buf + i, avail, &ic->hex_off);
            }
            i += avail;
            break;
        }
        }
    }
}
