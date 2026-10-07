#include "mitmssl.h"

EVP_PKEY *g_ca_key  = NULL;
X509     *g_ca_cert = NULL;
EVP_PKEY *g_leaf_key = NULL;
SSL_CTX  *g_client_ctx = NULL;
SSL_CTX  *g_server_ctx = NULL;
const char *g_logdir = ".";
int g_insecure = 0;

static void die(const char *msg)
{
    fprintf(stderr, APP_NAME ": %s\n", msg);
    exit(1);
}

static void ssl_die(const char *msg)
{
    fprintf(stderr, APP_NAME ": %s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(1);
}

static EVP_PKEY *load_key(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    EVP_PKEY *k = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    return k;
}

static X509 *load_cert(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    X509 *c = PEM_read_X509(f, NULL, NULL, NULL);
    fclose(f);
    return c;
}

int ca_load(const char *keypath, const char *certpath)
{
    g_ca_key = load_key(keypath);
    g_ca_cert = load_cert(certpath);
    if (!g_ca_key || !g_ca_cert) return -1;
    return 0;
}

int ca_generate(const char *keypath, const char *certpath)
{
    g_ca_key = EVP_RSA_gen(2048);
    if (!g_ca_key) ssl_die("RSA key generation failed");

    g_ca_cert = X509_new();
    if (!g_ca_cert) ssl_die("X509_new failed");

    ASN1_INTEGER_set(X509_get_serialNumber(g_ca_cert), 1);
    X509_gmtime_adj(X509_get_notBefore(g_ca_cert), 0);
    X509_gmtime_adj(X509_get_notAfter(g_ca_cert), 10 * 365 * 24 * 3600L);

    X509_NAME *name = X509_get_subject_name(g_ca_cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (const unsigned char *)"mitmssl CA", -1, -1, 0);
    X509_set_issuer_name(g_ca_cert, name);

    X509_set_version(g_ca_cert, 2);
    X509_set_pubkey(g_ca_cert, g_ca_key);

    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, g_ca_cert, g_ca_cert, NULL, NULL, 0);
    X509_EXTENSION *e = X509V3_EXT_conf_nid(NULL, &ctx,
                                            NID_basic_constraints,
                                            "critical,CA:TRUE");
    if (!e) ssl_die("basicConstraints failed");
    X509_add_ext(g_ca_cert, e, -1);
    X509_EXTENSION_free(e);

    e = X509V3_EXT_conf_nid(NULL, &ctx, NID_key_usage,
                            "critical,keyCertSign,cRLSign");
    if (!e) ssl_die("keyUsage failed");
    X509_add_ext(g_ca_cert, e, -1);
    X509_EXTENSION_free(e);

    if (!X509_sign(g_ca_cert, g_ca_key, EVP_sha256()))
        ssl_die("X509_sign failed");

    FILE *kf = fopen(keypath, "w");
    if (!kf) die("cannot open CA key file for writing");
    PEM_write_PrivateKey(kf, g_ca_key, NULL, NULL, 0, NULL, NULL);
    fclose(kf);

    FILE *cf = fopen(certpath, "w");
    if (!cf) die("cannot open CA cert file for writing");
    PEM_write_X509(cf, g_ca_cert);
    fclose(cf);

    return 0;
}
