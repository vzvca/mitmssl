# mitmssl

SSL interception proxy for inspection, written in C with OpenSSL.

mitmssl terminates TLS on the client side, opens a real TLS connection to the
upstream server, and forges on the fly a certificate for the emulated server,
signed by a local CA whose key the proxy owns. The client must trust this CA.
The goal is to debug client/server exchanges by decoding them.

## How it works

```
client --TLS--> mitmssl --TLS--> real server
        (cert forged by local CA)   (normal verification)
```

- Listens on `127.0.0.1:8080` (configurable) as an HTTP `CONNECT` proxy.
- ALPN-aware: selects `http/1.1` with the client, restricts the upstream
to `http/1.1`, and reports the negotiated protocol per flow.
- Generates a root CA (`ca.key` / `ca.crt`) on first run, reuses it afterwards.
- Choreographed handshakes: on the client's ClientHello, extracts the SNI,
  connects to the upstream server first (with that SNI), reads its real
  certificate, clones it (subject, SANs, extensions) signed by the local CA,
  and serves the clone to the client. In transparent mode without SNI, the
  upstream's default certificate is cloned. Every handshake step is
  reported on stdout (see Handshake trace).
- Relays the decoded traffic to stdout with per-flow framing (see below).

## Build

OpenSSL 3.5.7 is bundled as a git submodule and linked statically
(no runtime dependency on the system OpenSSL; works on older distros
such as Debian 11):

    git submodule update --init
    make

The first build compiles OpenSSL once (a few minutes); subsequent builds
only relink mitmssl. `make distclean` also cleans the OpenSSL tree.

## Usage

    ./mitmssl [-l PORT] [-k] [-m | -b] [-t] [-A PATH] [-C KEY,CERT]

- `-l PORT` listen port (default 8080)
- `-k`       skip upstream certificate verification (debug only)
- `-m`       MIME-aware rendering (text mode only): decode HTTP framing;
  dump text bodies as-is, hexdump binary bodies (`image/*`, `audio/*`,
  `video/*`, `application/...`); non-HTTP flows fall back to a
  printable-ratio heuristic
- `-b`       binary framing (see below) instead of text framing
- `-t`       transparent mode (see the Transparent mode section)
- `-A PATH`  trust store for upstream verification: a bundle file (e.g.
  `/etc/ssl/certs/ca-certificates.crt`) or a hashed directory (e.g.
  `/etc/ssl/certs`); by default the system locations are probed
- `-C KEY,CERT` CA key and cert paths (default `ca.key,ca.crt`,
  generated if missing)

`-m` and `-b` are mutually exclusive: `-m` renders payloads for human
reading, while `-b` emits raw bytes for machine consumers. The program
rejects the combination.

Example (explicit proxy mode):

    ./mitmssl -l 8080 | tee capture.txt
    curl -x http://127.0.0.1:8080 --cacert ca.crt https://example.com/

Install `ca.crt` in the client trust store so forged certificates are
accepted. Do not disable certificate verification on the client instead.

## Output framing

All decoded traffic is written to stdout, interleaved across concurrent
flows; each frame carries the id of its flow (a per-process monotonic
counter starting at 1, never reused). Use shell pipes to process the
stream (`tee`, `grep`, your own tool, ...).

Text framing (default):

    # 7 OPEN example.com:443 alpn=http/1.1
    7 -- client hello: sni=example.com
    7 -- upstream TLS ok: TLSv1.3 cipher=TLS_AES_256_GCM_SHA384
    7 -- cloned upstream cert: subject=example.com
    7 -- client TLS ok: TLSv1.3 cipher=TLS_AES_256_GCM_SHA384 alpn=http/1.1
    7 >> 122
    <122 raw bytes, client to server>
    7 << 139
    <139 raw bytes, server to client>
    7 ## EOF

`# ... OPEN` is emitted when the flow starts (destination known from
the CONNECT request or SO_ORIGINAL_DST; the `alpn=` suffix appears once
the client negotiates ALPN). `-- ...` lines are handshake and lifecycle
steps (see Handshake trace). `>>`/`<<` carry the decoded application
bytes; `## EOF` closes the flow. With `-m`, the payload of `>>`/`<<`
frames is rendered (HTTP headers kept, text bodies as-is, binary bodies
hexdumped) instead of raw bytes.

Binary framing (`-b`), for machine consumers: each frame is a 12-byte
header followed by `sz` payload bytes:

    struct frame {
        int32_t op;   /* 1=OPEN, 2=IN (c2s), 3=OUT (s2c), 4=EOF, 5=STEP */
        int32_t sz;   /* payload size, may be 0 */
        int32_t id;   /* flow id, monotonic, never reused */
        /* uint8_t data[sz]; */
    };

The OPEN payload is the destination `host:port` string (the `alpn=`
suffix is appended once ALPN is negotiated). IN/OUT payloads are raw
decoded bytes. EOF has sz=0. STEP payloads are human-readable step
strings, same content as the text `--` lines. Fields are
native-endian int32.

The header `mitmssl_frame.h` at the repository root provides the
authoritative definitions (frame header struct and op constants) for
tools that consume the binary stream:

    #include "mitmssl_frame.h"

## Handshake trace

The TLS choreography is reported step by step on stdout, in both framings.
Text mode emits `-- ` lines; binary mode uses op 5 (STEP) frames:

    # 1 OPEN example.com:443
    1 -- client hello: sni=example.com
    1 -- connecting to upstream example.com:443
    1 -- upstream connected example.com:443
    1 -- upstream TLS ok: TLSv1.3 cipher=TLS_AES_256_GCM_SHA384
    1 -- cloned upstream cert: subject=example.com
    1 -- client TLS ok: TLSv1.3 cipher=TLS_AES_256_GCM_SHA384 alpn=
    1 >> 56
    ...
    1 ## EOF

Failures are traced the same way (`upstream connect failed`, `upstream TLS
handshake failed`, `client TLS handshake failed`), followed by EOF.

## Certificate cloning

The served certificate is a clone of the upstream server's real
certificate: same subject, SANs and most extensions, but signed by the
mitmssl CA and bound to the proxy's leaf key. This maximizes client
compatibility (multi-SAN certificates, unusual EKUs) and handles the
transparent case without SNI (the upstream's default certificate is
cloned). Extensions that reference the real issuer's infrastructure
(AIA/OCSP) are stripped, since they would break validation.

## ALPN handling

The proxy advertises and selects `http/1.1` only, both toward the client
and toward the upstream server. Clients offering `h2` fall back to
`http/1.1` (or to no ALPN if they offer none); the connection fails only
if the client requires `h2` exclusively. The negotiated protocol is
reported in the OPEN frame (`alpn=http/1.1` in text mode, suffix in the
OPEN payload in binary mode). Relaying HTTP/2 would require HPACK
re-encoding and is not implemented.

## Transparent mode

With `-t`, mitmssl does not parse a `CONNECT` request: it expects raw TLS
connections and recovers the destination with `SO_ORIGINAL_DST`
(Linux Netfilter NAT). It therefore runs behind an iptables/nftables
REDIRECT rule.

### Same machine as the client (loopback)

When mitmssl listens on the loopback of the client machine, only the
`OUTPUT` rules apply: locally generated traffic never traverses
`PREROUTING`. A `PREROUTING` rule is useless in this setup.

The proxy listens on both `127.0.0.1` and `[::1]` (when IPv6 is
available). Most systems prefer IPv6 when the network allows it, so
**without the ip6tables rule the traffic silently bypasses the proxy**.
Post the rules in both families:

    ./mitmssl -t -l 8443
    iptables  -t nat -A OUTPUT -p tcp --dport 443 -m owner ! --uid-owner mitmssl \
        -j REDIRECT --to-port 8443
    ip6tables -t nat -A OUTPUT -p tcp --dport 443 -m owner ! --uid-owner mitmssl \
        -j REDIRECT --to-port 8443

To force IPv4-only during tests, use `curl -4` or equivalent.

### NAT gateway

On a gateway forwarding client traffic, both chains are needed:
`PREROUTING` for forwarded client traffic, `OUTPUT` (with the uid
exclusion) for the proxy's own upstream connections. Repeat in both
address families if the network carries IPv6:

    ./mitmssl -t -l 8443
    iptables  -t nat -A PREROUTING -i eth0 -p tcp --dport 443 \
        -j REDIRECT --to-port 8443
    iptables  -t nat -A OUTPUT -p tcp --dport 443 -m owner ! --uid-owner mitmssl \
        -j REDIRECT --to-port 8443
    ip6tables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 \
        -j REDIRECT --to-port 8443
    ip6tables -t nat -A OUTPUT -p tcp --dport 443 -m owner ! --uid-owner mitmssl \
        -j REDIRECT --to-port 8443

### Avoiding the redirection loop (critical)

Without a guard, the packets mitmssl itself sends to the real servers
(destination port 443) are redirected back to mitmssl: the proxy would
connect to itself in an infinite loop. The `-m owner ! --uid-owner mitmssl`
rule on `OUTPUT` prevents this: Netfilter matches the uid of the emitting
socket, so the proxy's own traffic is exempted.

This requires a dedicated user and running the proxy under it:

    useradd -r -s /usr/sbin/nologin mitmssl
    sudo -u mitmssl ./mitmssl -t -l 8443

The proxy MUST run under the dedicated uid, or the loop occurs.

### Excluding by cgroup instead of uid (root daemons)

If the proxy must run as root, exclude its traffic by cgroup instead of
uid. Two options:

cgroup v1 (`net_cls`):

    mkdir /sys/fs/cgroup/net_cls/mitmssl
    echo 0x0001 > /sys/fs/cgroup/net_cls/mitmssl/net_cls.classid
    echo $$ > /sys/fs/cgroup/net_cls/mitmssl/tasks
    ./mitmssl -t -l 8443
    iptables -t nat -A OUTPUT -p tcp --dport 443 -m mark ! --mark 1 \
        -j REDIRECT --to-port 8443

cgroup v2 (match by path, e.g. under systemd):

    systemd-run --unit=mitmssl --slice=mitmssl.slice \
        ./mitmssl -t -l 8443
    iptables -t nat -A OUTPUT -p tcp --dport 443 \
        -m cgroup ! --path mitmssl.slice \
        -j REDIRECT --to-port 8443

With `-m mark ! --mark 1`, packets carrying no mark also match the
negation, so make sure nothing else uses class 1.

## Protocol-agnostic inspection

The proxy only terminates TLS and relays bytes; it does not assume HTTP.
Any protocol over TLS/SSL is intercepted and logged. With `-m`, HTTP
framing (Content-Length, chunked) is additionally understood to hexdump
binary bodies; other protocols are heuristically dumped.

## Limitations

- Only http/1.1 is relayed (ALPN: h2 is refused, see ALPN handling).
- No session resumption on the client side.
- The proxy binds to loopback only.
- Transparent mode requires Linux Netfilter NAT (`SO_ORIGINAL_DST` /
  `IP6T_SO_ORIGINAL_DST`); both IPv4 and IPv6 are supported. If IPv6
  is unavailable, the proxy logs it and serves IPv4 only.

## Load testing

`scripts/loadtest.py` drives simultaneous tunnels through the proxy
against real hosts (a few hundred bytes per client, no heavy traffic):

    ./mitmssl -l 3333 > /dev/null 2> mitmssl.err &
    python3 scripts/loadtest.py -p 3333 -c 50 -n 200 --ca ca.crt \
        --hosts github.com,www.google.com

`-c` is the number of concurrent clients, `-n` the total number of
tunnels. The script validates the forged certificates, sends one HTTP
request per tunnel, and reports success rate, latency percentiles and
error categories. Add `-b` to the proxy to also verify binary frame
integrity under concurrency.

For transparent mode, run the proxy with `-t` behind the iptables
REDIRECT rule (see Transparent mode), then add `--transparent` to the
script: clients then send raw TLS straight to the proxy port, as the NAT
would deliver it. Without the NAT rule in place the proxy cannot recover
the destination and closes the connections immediately.

## License

MIT
