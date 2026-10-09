#include "mitmssl.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Extensions that must not be copied into a forged certificate:
 * they reference the real issuer's infrastructure and would break
 * client validation (AIA/OCSP URLs, Certificate Transparency SCTs). */
static const char *g_skip_ext[] = {
    "authorityInfoAccess",
    NULL
};

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

static X509 *build_cert(const char *cn, const char *san,
                       long valid_secs, X509 *copy_from)
{
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
    X509_gmtime_adj(X509_get_notAfter(cert), valid_secs);

    X509_NAME *name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (const unsigned char *)cn, -1, -1, 0);
    X509_set_issuer_name(cert, X509_get_subject_name(g_ca_cert));

    X509_set_version(cert, 2);
    X509_set_pubkey(cert, g_leaf_key);

    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, g_ca_cert, cert, NULL, NULL, 0);
    X509V3_set_ctx_nodb(&ctx);

    if (copy_from) {
        int last = X509_get_ext_count(copy_from);
        for (int i = 0; i < last; i++) {
            X509_EXTENSION *e = X509_get_ext(copy_from, i);
            if (!e) continue;
            ASN1_OBJECT *obj = X509_EXTENSION_get_object(e);
            char objname[64];
            if (OBJ_obj2txt(objname, sizeof(objname), obj, 0) <= 0)
                continue;
            int skip = 0;
            for (int j = 0; g_skip_ext[j]; j++) {
                if (strcmp(objname, g_skip_ext[j]) == 0) { skip = 1; break; }
            }
            if (skip) continue;
            X509_EXTENSION *dup = X509_EXTENSION_dup(e);
            if (!dup) continue;
            X509_add_ext(cert, dup, -1);
            X509_EXTENSION_free(dup);
        }
    } else {
        X509_EXTENSION *e = X509V3_EXT_conf_nid(NULL, &ctx,
                                                NID_subject_alt_name,
                                                (char *)san);
        if (e) {
            X509_add_ext(cert, e, -1);
            X509_EXTENSION_free(e);
        }
        e = X509V3_EXT_conf_nid(NULL, &ctx, NID_basic_constraints,
                                "critical,CA:FALSE");
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
    }

    if (!X509_sign(cert, g_ca_key, EVP_sha256())) {
        X509_free(cert);
        return NULL;
    }
    return cert;
}

X509 *clone_cert(X509 *orig, char *subject_out, size_t subject_cap)
{
    if (!orig) return NULL;

    char cn[256] = "unknown.local";
    X509_NAME *subj = X509_get_subject_name(orig);
    if (subj) {
        int idx = X509_NAME_get_index_by_NID(subj, NID_commonName, -1);
        if (idx >= 0) {
            ASN1_STRING *cn_asn1 = X509_NAME_ENTRY_get_data(
                X509_NAME_get_entry(subj, idx));
            if (cn_asn1) {
                unsigned char *cn_buf = NULL;
                int len = ASN1_STRING_to_UTF8(&cn_buf, cn_asn1);
                if (len > 0 && cn_buf) {
                    size_t copy = (size_t)len < sizeof(cn) ? (size_t)len
                                                           : sizeof(cn) - 1;
                    memcpy(cn, cn_buf, copy);
                    cn[copy] = 0;
                    OPENSSL_free(cn_buf);
                }
            }
        }
    }

    if (subject_out)
        snprintf(subject_out, subject_cap, "%s", cn);

    X509 *cert = build_cert(cn, NULL, 365 * 24 * 3600L, orig);
    return cert;
}

X509 *forge_cert(const char *host)
{
    X509 *cached = cache_get(host);
    if (cached) return cached;

    char san[512];
    struct in_addr ia;
    struct in6_addr ia6;
    if (inet_pton(AF_INET, host, &ia) == 1)
        snprintf(san, sizeof(san), "IP:%s", host);
    else if (inet_pton(AF_INET6, host, &ia6) == 1)
        snprintf(san, sizeof(san), "IP:%s", host);
    else
        snprintf(san, sizeof(san), "DNS:%s", host);

    X509 *cert = build_cert(host, san, 365 * 24 * 3600L, NULL);
    if (!cert) return NULL;

    cache_put(host, cert);
    return cert;
}
