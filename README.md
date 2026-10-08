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
- Generates a root CA (`ca.key` / `ca.crt`) on first run, reuses it afterwards.
- For each tunnel, reads the SNI (or the CONNECT host), forges a leaf
  certificate signed by the CA, completes the handshake with the client, then
  connects to the upstream server over TLS.
- Relays and logs the decoded traffic in clear text:
  - `<logdir>/<host>:<port>.c2s` - client to server
  - `<logdir>/<host>:<port>.s2c` - server to client

## Build

Requires OpenSSL development headers and lib (1.1.1 or 3.x):

    make

## Usage

    ./mitmssl [-l PORT] [-c LOGDIR] [-k] [-C KEY,CERT]

- `-l PORT` listen port (default 8080)
- `-c DIR`  log directory (default `logs`)
- `-k`       skip upstream certificate verification (debug only)
- `-m`       MIME-aware logging: decode HTTP framing; dump text bodies as-is,
  hexdump binary bodies (`image/*`, `audio/*`, `video/*`, `application/...`);
  non-HTTP flows fall back to a printable-ratio heuristic
- `-e CMD`   pipe decoded traffic to a helper program, one process per flow.
  `%h`/`%p` in CMD expand to host/port; stdin receives a simple framing:
  `>> <n>\n` + n bytes (client to server), `<< <n>\n` + n bytes
  (server to client), `## EOF\n` at flow end. Example: `-e cat` to print.
- `-t`       transparent mode: recover the destination with
  `SO_ORIGINAL_DST` (Linux Netfilter NAT) instead of parsing a `CONNECT`
  request; pairs with an iptables/nftables redirect rule
- `-C KEY,CERT` CA key and cert paths (default `ca.key,ca.crt`,
  generated if missing)

Example (explicit proxy mode):

    ./mitmssl -l 8080 -c logs
    curl -x http://127.0.0.1:8080 --cacert ca.crt https://example.com/

Example (transparent mode, on the NAT gateway):

    ./mitmssl -t -l 8443 -c logs
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
    sudo -u mitmssl ./mitmssl -t -l 8443 -c logs

Notes:

- On the same machine as the client, only the `OUTPUT` rule applies
  (locally generated traffic never traverses `PREROUTING`); the proxy
  MUST run under the dedicated uid or the loop occurs.
- On a gateway, both rules are needed: `PREROUTING` for forwarded
  client traffic, `OUTPUT` (with the uid exclusion) for the proxy's own
  upstream connections.
- If the proxy must run as root, exclude its traffic by cgroup mark
  (`net_cls` + `--mark`) instead of uid.

Install `ca.crt` in the client trust store so forged certificates are
accepted. Do not disable certificate verification on the client instead.

## Protocol-agnostic inspection

The proxy only terminates TLS and relays bytes; it does not assume HTTP.
Any protocol over TLS/SSL is intercepted and logged. With `-m`, HTTP
framing (Content-Length, chunked) is additionally understood to hexdump
binary bodies; other protocols are heuristically dumped.

## Limitations

- HTTP/1.x only (ALPN `h2` is not negotiated upstream).
- No session resumption on the client side.
- The proxy binds to loopback only.
- Transparent mode requires Linux Netfilter NAT (`SO_ORIGINAL_DST`) and
  typically runs on the gateway as root.

## License

MIT
