#!/usr/bin/env python3
"""
scripts/generate_traffic.py

A traffic generator that simulates concurrent client requests to the
NetGuardian proxy. Simulates normal traffic alongside attack payloads
(SQLi, Header injection) to demonstrate IDS/IPS detection and filtering.
"""

import argparse
import asyncio
import random
import urllib.parse
from typing import List


# Pre-defined payloads for simulation
NORMAL_PATHS = [
    "/",
    "/index.html",
    "/about",
    "/contact",
    "/static/style.css",
    "/static/bundle.js",
    "/api/v1/status",
]

ATTACK_PATHS = [
    "/login?user=admin'%20OR%201=1--",
    "/search?q=1%20UNION%20SELECT%20*%20FROM%20users",
    "/delete?id=1;%20DROP%20TABLE%20logs",
    "/?exploit=evil-exploit",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "curl/8.4.0",
]


async def send_request(
    proxy_host: str,
    proxy_port: int,
    target_host: str,
    target_port: int,
    path: str,
    headers: dict,
    req_id: int,
) -> None:
    """Send an HTTP request via the proxy to the target."""
    try:
        reader, writer = await asyncio.open_connection(proxy_host, proxy_port)
    except Exception as e:
        print(f"[{req_id}] Failed to connect to proxy: {e}")
        return

    try:
        # Construct proxy request line
        req_line = f"GET http://{target_host}:{target_port}{path} HTTP/1.1\r\n"
        req_headers = f"Host: {target_host}:{target_port}\r\n"
        for k, v in headers.items():
            req_headers += f"{k}: {v}\r\n"
        req_headers += "\r\n"

        full_request = (req_line + req_headers).encode("utf-8")

        writer.write(full_request)
        await writer.drain()

        # Read status line
        response_data = await reader.read(1024)
        status_line = ""
        if response_data:
            first_line = response_data.split(b"\r\n")[0]
            status_line = first_line.decode("utf-8", errors="replace")

        print(f"[{req_id}] Path: {path:<45} -> Status: {status_line}")

    except Exception as e:
        print(f"[{req_id}] Error: {e}")
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def worker(
    worker_id: int,
    proxy_host: str,
    proxy_port: int,
    target_host: str,
    target_port: int,
    total_requests: int,
    attack_ratio: float,
) -> None:
    """Worker task that sends a series of random requests."""
    for i in range(total_requests):
        is_attack = random.random() < attack_ratio
        path = random.choice(ATTACK_PATHS) if is_attack else random.choice(NORMAL_PATHS)

        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "Connection": "close",
        }

        # Header anomaly simulations
        if random.random() < 0.05:
            # Missing Host header
            headers = {"User-Agent": "curl/8.4.0", "Connection": "close"}
        if random.random() < 0.05:
            # Header CRLF injection
            headers["X-Injection-Test"] = "Injecting\r\nEvil-Header: true"

        await send_request(
            proxy_host,
            proxy_port,
            target_host,
            target_port,
            path,
            headers,
            worker_id * 1000 + i,
        )
        await asyncio.sleep(random.uniform(0.1, 0.5))


async def main() -> None:
    parser = argparse.ArgumentParser(description="NetGuardian Traffic Generator")
    parser.add_argument("--proxy-host", default="127.0.0.1", help="Proxy host IP")
    parser.add_argument("--proxy-port", type=int, default=8080, help="Proxy port")
    parser.add_argument("--target-host", default="example.com", help="Target backend host")
    parser.add_argument("--target-port", type=int, default=80, help="Target backend port")
    parser.add_argument("--concurrency", type=int, default=5, help="Number of concurrent clients")
    parser.add_argument("--requests", type=int, default=10, help="Requests per client")
    parser.add_argument("--attack-ratio", type=float, default=0.2, help="Ratio of requests that are attacks (0.0 - 1.0)")

    args = parser.parse_args()

    print(f"Starting traffic generator...")
    print(f"Proxy:   {args.proxy_host}:{args.proxy_port}")
    print(f"Target:  {args.target_host}:{args.target_port}")
    print(f"Clients: {args.concurrency} running concurrently")
    print(f"Total:   {args.concurrency * args.requests} requests will be sent")

    workers = [
        worker(
            i,
            args.proxy_host,
            args.proxy_port,
            args.target_host,
            args.target_port,
            args.requests,
            args.attack_ratio,
        )
        for i in range(args.concurrency)
    ]

    await asyncio.gather(*workers)
    print("Traffic generation complete.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nStopping traffic generator.")
