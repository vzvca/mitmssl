#!/usr/bin/env python3
"""Load test for mitmssl: many simultaneous CONNECT tunnels through the proxy.

Each simulated client opens a CONNECT tunnel, performs a TLS handshake
(validating the forged certificate against the mitmssl CA), sends one small
HTTP request, and closes. Traffic per client is a few hundred bytes.

Usage:
    ./loadtest.py -p 3333 -c 50 [-n 200] [--hosts github.com,google.com]
                  [--ca ca.crt] [--timeout 10]

Reports success rate, latency percentiles, and errors by category.
"""

import argparse
import socket
import ssl
import sys
import threading
import time
from collections import Counter

DEFAULT_HOSTS = ["github.com", "www.google.com", "example.com"]


def one_request(proxy_host, proxy_port, host, cafile, timeout):
    t0 = time.monotonic()
    try:
        s = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n"
                  .encode())
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = s.recv(4096)
            if not chunk:
                return ("connect-closed", time.monotonic() - t0)
            resp += chunk
        if b" 200 " not in resp.split(b"\r\n")[0]:
            return ("connect-rejected", time.monotonic() - t0)

        ctx = ssl.create_default_context(cafile=cafile)
        w = ctx.wrap_socket(s, server_hostname=host)
        req = (f"GET / HTTP/1.1\r\nHost: {host}\r\n"
               "User-Agent: mitmssl-loadtest\r\nConnection: close\r\n\r\n")
        w.sendall(req.encode())
        total = 0
        first = w.recv(256)
        if not first:
            return ("empty-response", time.monotonic() - t0)
        total = len(first)
        while True:
            try:
                chunk = w.recv(4096)
            except (socket.timeout, ssl.SSLError):
                break
            if not chunk:
                break
            total += chunk.size() if hasattr(chunk, "size") else len(chunk)
        w.close()
        return ("ok", time.monotonic() - t0)
    except ssl.SSLCertVerificationError as e:
        return ("cert-error", time.monotonic() - t0)
    except ssl.SSLError as e:
        return ("ssl-error", time.monotonic() - t0)
    except socket.timeout:
        return ("timeout", time.monotonic() - t0)
    except OSError as e:
        return ("network-error", time.monotonic() - t0)


def percentile(sorted_vals, p):
    if not sorted_vals:
        return 0.0
    k = min(len(sorted_vals) - 1, int(len(sorted_vals) * p / 100))
    return sorted_vals[k]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-p", "--port", type=int, default=3333)
    ap.add_argument("--proxy-host", default="127.0.0.1")
    ap.add_argument("-c", "--concurrency", type=int, default=50)
    ap.add_argument("-n", "--total", type=int, default=200)
    ap.add_argument("--hosts", default=",".join(DEFAULT_HOSTS))
    ap.add_argument("--ca", default="ca.crt")
    ap.add_argument("--timeout", type=float, default=10.0)
    args = ap.parse_args()

    hosts = [h.strip() for h in args.hosts.split(",") if h.strip()]
    results = []
    errors = Counter()
    lock = threading.Lock()
    counter = {"done": 0}

    def worker():
        while True:
            with lock:
                i = counter["done"]
                if i >= args.total:
                    return
                counter["done"] = i + 1
            host = hosts[i % len(hosts)]
            r = one_request(args.proxy_host, args.port, host,
                            args.ca, args.timeout)
            with lock:
                results.append(r)

    t_start = time.monotonic()
    threads = [threading.Thread(target=worker)
               for _ in range(args.concurrency)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.monotonic() - t_start

    ok_times = sorted(d for status, d in results if status == "ok")
    for status, _ in results:
        if status != "ok":
            errors[status] += 1

    n_ok = len(ok_times)
    print(f"total: {len(results)}  ok: {n_ok}  "
          f"failed: {len(results) - n_ok}  wall: {elapsed:.2f}s  "
          f"throughput: {len(results)/elapsed:.1f} conn/s")
    if ok_times:
        print(f"latency ms: p50={percentile(ok_times,50)*1000:.0f}  "
              f"p90={percentile(ok_times,90)*1000:.0f}  "
              f"p99={percentile(ok_times,99)*1000:.0f}  "
              f"max={ok_times[-1]*1000:.0f}")
    if errors:
        print("errors:", dict(errors))
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())
