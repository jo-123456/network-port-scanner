#!/usr/bin/env python3
"""
port_scanner.py - TCP connect() port auditor with service responsiveness checks.

Classifies each port as:
  OPEN     - TCP three-way handshake completed
  CLOSED   - host actively refused the connection (RST received)
  FILTERED - no answer within the timeout, or ICMP unreachable
             (typically a firewall silently dropping packets)

For open ports it also measures connect latency and tries to read a service
banner (or sends a minimal HTTP HEAD request) to confirm the service responds.

USE ONLY ON HOSTS YOU OWN OR HAVE WRITTEN PERMISSION TO TEST.
"""

import argparse
import errno
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Step 1: socket library imported above.

COMMON_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 143: "imap", 443: "https", 445: "smb", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 6379: "redis", 8000: "http-alt",
    8080: "http-alt", 8443: "https-alt", 27017: "mongodb",
}
HTTP_PORTS = {80, 8000, 8080, 8888}

OPEN, CLOSED, FILTERED = "OPEN", "CLOSED", "FILTERED"


def probe_service(sock, host, port, timeout):
    """Check whether an open port actually answers. Returns a short string."""
    sock.settimeout(timeout)
    try:
        if port in HTTP_PORTS:
            req = f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode()
            sock.sendall(req)
        data = sock.recv(256)
        if not data:
            return "connected, closed by peer"
        first_line = data.decode("utf-8", errors="replace").splitlines()[0]
        return f"responsive: {first_line[:50]!r}"
    except socket.timeout:
        return "connected, no banner (silent service)"
    except OSError as exc:
        return f"connected, probe error ({exc.strerror})"


def scan_port(host, port, timeout, probe):
    """Step 3: attempt a TCP handshake with a timeout. Returns a result dict."""
    result = {"port": port, "state": FILTERED, "latency_ms": None, "detail": ""}
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    start = time.perf_counter()
    try:
        code = sock.connect_ex((host, port))
        elapsed = (time.perf_counter() - start) * 1000
        if code == 0:
            result.update(state=OPEN, latency_ms=elapsed)
            if probe:
                result["detail"] = probe_service(sock, host, port, timeout)
        elif code == errno.ECONNREFUSED:
            result.update(state=CLOSED, latency_ms=elapsed, detail="connection refused")
        elif code in (errno.EHOSTUNREACH, errno.ENETUNREACH, errno.ETIMEDOUT):
            result.update(state=FILTERED, detail=errno.errorcode.get(code, str(code)))
        else:
            result.update(state=FILTERED, detail=errno.errorcode.get(code, f"errno {code}"))
    except socket.timeout:
        result.update(state=FILTERED, detail="timed out (no response)")
    except OSError as exc:
        result.update(state=FILTERED, detail=str(exc))
    finally:
        sock.close()
    return result


def compress_ranges(ports):
    """[1,2,3,7,9,10] -> '1-3, 7, 9-10'"""
    if not ports:
        return "-"
    ports = sorted(ports)
    parts, start, prev = [], ports[0], ports[0]
    for p in ports[1:]:
        if p == prev + 1:
            prev = p
            continue
        parts.append(f"{start}-{prev}" if start != prev else f"{start}")
        start = prev = p
    parts.append(f"{start}-{prev}" if start != prev else f"{start}")
    return ", ".join(parts)


def print_table(results, show_closed):
    """Step 4: display a table of Open / Closed / Filtered ports."""
    rows = [r for r in results if show_closed or r["state"] != CLOSED]
    header = f"{'PORT':<7}{'STATE':<10}{'SERVICE':<12}{'LATENCY':<11}DETAIL"
    print(header)
    print("-" * max(len(header), 70))
    for r in rows:
        lat = f"{r['latency_ms']:.2f} ms" if r["latency_ms"] is not None else "-"
        svc = COMMON_SERVICES.get(r["port"], "unknown")
        print(f"{r['port']:<7}{r['state']:<10}{svc:<12}{lat:<11}{r['detail']}")
    if not rows:
        print("(no open or filtered ports)")
    print("-" * max(len(header), 70))

    by_state = {s: [r["port"] for r in results if r["state"] == s]
                for s in (OPEN, CLOSED, FILTERED)}
    print("\nSUMMARY")
    for s in (OPEN, CLOSED, FILTERED):
        print(f"  {s:<9}: {len(by_state[s]):>5}   ports: {compress_ranges(by_state[s])}")


def parse_args():
    p = argparse.ArgumentParser(description="TCP port audit utility (authorized use only).")
    p.add_argument("target", nargs="?", help="target IP address or hostname")
    p.add_argument("-p", "--ports", help="port range, e.g. 1-1024, or list 22,80,443")
    p.add_argument("-t", "--timeout", type=float, default=1.0,
                   help="per-port timeout in seconds (default 1.0)")
    p.add_argument("-w", "--workers", type=int, default=100,
                   help="concurrent threads (default 100)")
    p.add_argument("--no-probe", action="store_true", help="skip service/banner probe")
    p.add_argument("--show-closed", action="store_true",
                   help="list every closed port in the table (default: summary only)")
    return p.parse_args()


def parse_ports(spec):
    ports = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if "-" in chunk:
            lo, hi = (int(x) for x in chunk.split("-", 1))
            if lo > hi:
                raise ValueError(f"invalid range: {chunk}")
            ports.update(range(lo, hi + 1))
        elif chunk:
            ports.add(int(chunk))
    if not ports or min(ports) < 1 or max(ports) > 65535:
        raise ValueError("ports must be within 1-65535")
    return sorted(ports)


def main():
    args = parse_args()

    # Step 2: accept target IP and port range (arguments or interactive prompt).
    target = args.target or input("Target IP / hostname: ").strip()
    port_spec = args.ports or input("Port range (e.g. 1-1024): ").strip()
    try:
        ports = parse_ports(port_spec)
        ip = socket.gethostbyname(target)
    except (ValueError, socket.gaierror) as exc:
        sys.exit(f"Input error: {exc}")

    print(f"Scan started : {datetime.now():%Y-%m-%d %H:%M:%S}")
    print(f"Target       : {target} ({ip})")
    print(f"Ports        : {compress_ranges(ports)} ({len(ports)} total)")
    print(f"Timeout      : {args.timeout}s   Workers: {args.workers}\n")

    t0 = time.perf_counter()
    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(scan_port, ip, p, args.timeout, not args.no_probe)
                   for p in ports]
        for fut in as_completed(futures):
            results.append(fut.result())
    results.sort(key=lambda r: r["port"])

    print_table(results, args.show_closed)
    print(f"\nScan finished in {time.perf_counter() - t0:.2f}s")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\nInterrupted by user.")
