/*
 * mitmssl - public definition of the binary output framing (-b).
 *
 * Consumers of mitmssl's stdout can include this header to decode the
 * frame stream. Each frame is a fixed 12-byte header immediately
 * followed by `sz` payload bytes. All fields are native-endian int32.
 *
 * The flow id (`id`) is a per-process monotonic counter starting at 1;
 * ids are never reused within a run.
 */
#ifndef MITMSSL_FRAME_H
#define MITMSSL_FRAME_H

#include <stdint.h>

struct mitmssl_frame_hdr {
    int32_t op;   /* one of the MITMSSL_OP_* constants below */
    int32_t sz;   /* payload size in bytes, may be 0 */
    int32_t id;   /* flow id, monotonic, never reused */
    /* followed by `sz` payload bytes */
};

enum {
    MITMSSL_OP_OPEN = 1,  /* payload: "host:port[ alpn=proto]" string */
    MITMSSL_OP_IN   = 2,  /* payload: raw decoded bytes, client to server */
    MITMSSL_OP_OUT  = 3,  /* payload: raw decoded bytes, server to client */
    MITMSSL_OP_EOF  = 4,  /* payload: none (sz == 0) */
    MITMSSL_OP_STEP = 5   /* payload: human-readable handshake/step string */
};

#endif /* MITMSSL_FRAME_H */
