#include "mitmssl.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

struct cache_ent {
    char *host;
    X509 *cert;
    struct cache_ent *next;
};

static struct cache_ent *g_cache = NULL;
static pthread_mutex_t g_cache_mu = PTHREAD_MUTEX_INITIALIZER;

static X509 *cache_get(const char *host)
{
    X509 *found = NULL;
    pthread_mutex_lock(&g_cache_mu);
    for (struct cache_ent *e = g_cache; e; e = e->next) {
        if (strcmp(e->host, host) == 0) {
            found = e->cert;
            break;
        }
    }
    pthread_mutex_unlock(&g_cache_mu);
    return found;
}

static void cache_put(const char *host, X509 *cert)
{
    struct cache_ent *e = malloc(sizeof(*e));
    if (!e) return;
    e->host = strdup(host);
    e->cert = cert;
    if (!e->host) { free(e); return; }
    pthread_mutex_lock(&g_cache_mu);
    e->next = g_cache;
    g_cache = e;
    pthread_mutex_unlock(&g_cache_mu);
}

X509 *forge_cert(const char *host)
{
    X509 *cached = cache_get(host);
    if (cached) return cached;

    X509 *cert = X509_new();
    if (!cert) return NULL;

    unsigned char serial[8];
    if (RAND_bytes(serial, sizeof(serial)) != 1) {
        X509_free(cert);
        return NULL;
    }
    ASN1_INTEGER *sn = X509_get_serialNumber(cert);
    ASN1_STRING_set(sn, serial, sizeof(serial));

    X509_gmtime_adj(X509_get_notBefore(cert), -3600);
    X509_gmtime_adj(X509_get_notAfter(cert), 365 * 24 * 3600L);

    X509_NAME *name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (const unsigned char *)host, -1, -1, 0);
    X509_set_issuer_name(cert, X509_get_subject_name(g_ca_cert));

    X509_set_version(cert, 2);
    X509_set_pubkey(cert, g_leaf_key);

    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, g_ca_cert, cert, NULL, NULL, 0);
    X509V3_set_ctx_nodb(&ctx);

    char san[512];
    struct in_addr ia;
    struct in6_addr ia6;
    if (inet_pton(AF_INET, host, &ia) == 1)
        snprintf(san, sizeof(san), "IP:%s", host);
    else if (inet_pton(AF_INET6, host, &ia6) == 1)
        snprintf(san, sizeof(san), "IP:%s", host);
    else
        snprintf(san, sizeof(san), "DNS:%s", host);

    X509_EXTENSION *e = X509V3_EXT_conf_nid(NULL, &ctx,
                                            NID_subject_alt_name, san);
    if (!e) {
        X509_free(cert);
        return NULL;
    }
    X509_add_ext(cert, e, -1);
    X509_EXTENSION_free(e);

    e = X509V3_EXT_conf_nid(NULL, &ctx, NID_basic_constraints, "CA:FALSE");
    if (e) {
        X509_add_ext(cert, e, -1);
        X509_EXTENSION_free(e);
    }
    e = X509V3_EXT_conf_nid(NULL, &ctx, NID_key_usage,
                            "critical,digitalSignature,keyEncipherment");
    if (e) {
        X509_add_ext(cert, e, -1);
        X509_EXTENSION_free(e);
    }
    e = X509V3_EXT_conf_nid(NULL, &ctx, NID_ext_key_usage, "serverAuth");
    if (e) {
        X509_add_ext(cert, e, -1);
        X509_EXTENSION_free(e);
    }

    if (!X509_sign(cert, g_ca_key, EVP_sha256())) {
        X509_free(cert);
        return NULL;
    }

    cache_put(host, cert);
    return cert;
}
