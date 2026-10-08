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
- For each tunnel, reads the SNI (or the CONNECT host), forges a leaf
  certificate signed by the CA, completes the handshake with the client, then
  connects to the upstream server over TLS.
- Relays the decoded traffic to stdout with per-flow framing (see below).

## Build

Requires OpenSSL development headers and lib (1.1.1 or 3.x):

    make

## Usage

    ./mitmssl [-l PORT] [-k] [-m] [-b] [-t] [-C KEY,CERT]

- `-l PORT` listen port (default 8080)
- `-k`       skip upstream certificate verification (debug only)
- `-m`       MIME-aware rendering: decode HTTP framing; dump text bodies as-is,
  hexdump binary bodies (`image/*`, `audio/*`, `video/*`, `application/...`);
  non-HTTP flows fall back to a printable-ratio heuristic
- `-b`       binary framing (see below) instead of text framing
- `-t`       transparent mode: recover the destination with
  `SO_ORIGINAL_DST` (Linux Netfilter NAT) instead of parsing a `CONNECT`
  request; pairs with an iptables/nftables redirect rule
- `-t`       transparent mode: recover the destination with
  `SO_ORIGINAL_DST` (Linux Netfilter NAT) instead of parsing a `CONNECT`
  request; pairs with an iptables/nftables redirect rule
- `-C KEY,CERT` CA key and cert paths (default `ca.key,ca.crt`,
  generated if missing)

Example (explicit proxy mode):

    ./mitmssl -l 8080 | tee capture.txt
    curl -x http://127.0.0.1:8080 --cacert ca.crt https://example.com/

## Output framing

All decoded traffic is written to stdout, interleaved across concurrent
flows; each frame carries the id of its flow (a monotonic counter, never
reused). Use shell pipes to process the stream (`tee`, `grep`, your own
tool, ...).

Text framing (default):

    # 7 OPEN example.com:443 alpn=http/1.1
    7 >> 122
    <122 raw bytes, client to server>
    7 << 139
    <139 raw bytes, server to client>
    7 ## EOF

With `-m`, the payload of `>>`/`<<` frames is rendered (HTTP headers kept,
text bodies as-is, binary bodies hexdumped) instead of raw bytes.

Binary framing (`-b`), for machine consumers: each frame is a 12-byte
header followed by `sz` payload bytes:

    struct frame {
        int32_t op;   /* 1=OPEN, 2=IN (c2s), 3=OUT (s2c), 4=EOF */
        int32_t sz;   /* payload size, may be 0 */
        int32_t id;   /* flow id, monotonic, never reused */
        /* uint8_t data[sz]; */
    };

The OPEN payload is the destination `host:port` string, optionally followed
by ` alpn=<proto>` when the client negotiated ALPN. IN/OUT payloads are
raw decoded bytes. EOF has sz=0. Fields are native-endian int32.

## ALPN handling

The proxy advertises and selects `http/1.1` only, both toward the client
and toward the upstream server. Clients offering `h2` fall back to
`http/1.1` (or to no ALPN if they offer none); the connection fails only
if the client requires `h2` exclusively. The negotiated protocol is
reported in the OPEN frame (`alpn=http/1.1` in text mode, suffix in the
OPEN payload in binary mode). Relaying HTTP/2 would require HPACK
re-encoding and is not implemented.

Example (transparent mode, on the NAT gateway):

    ./mitmssl -t -l 8443
    iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 \
        -j REDIRECT --to-port 8443
    iptables -t nat -A OUTPUT -p tcp --dport 443 -m owner ! --uid-owner mitmssl \
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

Notes:

- On the same machine as the client, only the `OUTPUT` rule applies
  (locally generated traffic never traverses `PREROUTING`); the proxy
  MUST run under the dedicated uid or the loop occurs.
- On a gateway, both rules are needed: `PREROUTING` for forwarded
  client traffic, `OUTPUT` (with the uid exclusion) for the proxy's own
  upstream connections.
- If the proxy must run as root, exclude its traffic by cgroup instead of
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

Install `ca.crt` in the client trust store so forged certificates are
accepted. Do not disable certificate verification on the client instead.

## Protocol-agnostic inspection

The proxy only terminates TLS and relays bytes; it does not assume HTTP.
Any protocol over TLS/SSL is intercepted and logged. With `-m`, HTTP
framing (Content-Length, chunked) is additionally understood to hexdump
binary bodies; other protocols are heuristically dumped.

## Limitations

- Only http/1.1 is relayed (ALPN: h2 is refused, see ALPN handling).
- No session resumption on the client side.
- The proxy binds to loopback only.
- Transparent mode requires Linux Netfilter NAT (`SO_ORIGINAL_DST`) and
  typically runs on the gateway as root.

## License

MIT
