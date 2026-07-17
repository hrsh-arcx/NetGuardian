#!/usr/bin/env python3
"""
scripts/benchmark.py

Measures NetGuardian proxy request latency, throughput, and comparison
to direct connections. Measures average, median, p95, and p99 response times.
"""

import argparse
import asyncio
import time
import socket
from typing import List, Tuple


async def measure_request(
    host: str,
    port: int,
    request_bytes: bytes,
) -> float:
    """Send an HTTP request and measure response latency in milliseconds."""
    start = time.perf_counter()
    try:
        reader, writer = await asyncio.open_connection(host, port)
        writer.write(request_bytes)
        await writer.drain()

        # Read only the first chunk of response (mimic head performance)
        await reader.read(1024)
        writer.close()
        await writer.wait_closed()
        return (time.perf_counter() - start) * 1000.0
    except Exception:
        return -1.0  # error


def print_stats(name: str, latencies: List[float]) -> None:
    """Print latency distribution summary."""
    valid_latencies = [l for l in latencies if l > 0]
    errors = len(latencies) - len(valid_latencies)

    if not valid_latencies:
        print(f"\n{name}: All requests failed.")
        return

    sorted_lat = sorted(valid_latencies)
    n = len(sorted_lat)
    avg = sum(sorted_lat) / n
    p50 = sorted_lat[int(n * 0.50)]
    p95 = sorted_lat[int(n * 0.95)]
    p99 = sorted_lat[min(int(n * 0.99), n - 1)]

    print(f"\n[+] {name} Statistics:")
    print(f"  * Total Requests: {len(latencies)}")
    print(f"  * Successful:     {n}")
    print(f"  * Failed:         {errors}")
    print(f"  * Min Latency:    {sorted_lat[0]:.2f} ms")
    print(f"  * Max Latency:    {sorted_lat[-1]:.2f} ms")
    print(f"  * Avg Latency:    {avg:.2f} ms")
    print(f"  * p50 (Median):   {p50:.2f} ms")
    print(f"  * p95:            {p95:.2f} ms")
    print(f"  * p99:            {p99:.2f} ms")


async def main() -> None:
    parser = argparse.ArgumentParser(description="NetGuardian Performance Benchmark Utility")
    parser.add_argument("--proxy-host", default="127.0.0.1", help="Proxy host IP")
    parser.add_argument("--proxy-port", type=int, default=8080, help="Proxy port")
    parser.add_argument("--target-host", default="127.0.0.1", help="Target server host")
    parser.add_argument("--target-port", type=int, required=True, help="Target backend server port (MUST be running)")
    parser.add_argument("--requests", type=int, default=100, help="Number of benchmark requests")
    parser.add_argument("--concurrency", type=int, default=10, help="Concurrency limit for benchmark")

    args = parser.parse_args()

    # Define HTTP request payloads
    # 1. Direct request payload to target
    direct_req = (
        f"GET /index.html HTTP/1.1\r\n"
        f"Host: {args.target_host}:{args.target_port}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("utf-8")

    # 2. Proxy request payload
    proxy_req = (
        f"GET http://{args.target_host}:{args.target_port}/index.html HTTP/1.1\r\n"
        f"Host: {args.target_host}:{args.target_port}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("utf-8")

    print(f"Running benchmarks...")
    print(f"Requests: {args.requests} | Concurrency: {args.concurrency}")

    # Semaphores to limit concurrency
    sem = asyncio.Semaphore(args.concurrency)

    async def run_direct():
        async with sem:
            return await measure_request(args.target_host, args.target_port, direct_req)

    async def run_proxy():
        async with sem:
            return await measure_request(args.proxy_host, args.proxy_port, proxy_req)

    # ──── Benchmark Direct Connection ────
    print("\n[1/2] Benchmarking direct connection to backend target...")
    start_time = time.perf_counter()
    direct_tasks = [run_direct() for _ in range(args.requests)]
    direct_results = await asyncio.gather(*direct_tasks)
    direct_duration = time.perf_counter() - start_time
    direct_rps = args.requests / direct_duration

    # ──── Benchmark Proxy Connection ────
    print("[2/2] Benchmarking connection through NetGuardian Proxy...")
    start_time = time.perf_counter()
    proxy_tasks = [run_proxy() for _ in range(args.requests)]
    proxy_results = await asyncio.gather(*proxy_tasks)
    proxy_duration = time.perf_counter() - start_time
    proxy_rps = args.requests / proxy_duration

    # ---- Display Results ----
    print_stats("Direct Connection", direct_results)
    print(f"  * Throughput:     {direct_rps:.2f} req/sec")

    print_stats("NetGuardian Proxy", proxy_results)
    print(f"  * Throughput:     {proxy_rps:.2f} req/sec")

    # Calculate Overhead
    valid_direct = [l for l in direct_results if l > 0]
    valid_proxy = [l for l in proxy_results if l > 0]
    if valid_direct and valid_proxy:
        avg_direct = sum(valid_direct) / len(valid_direct)
        avg_proxy = sum(valid_proxy) / len(valid_proxy)
        overhead = avg_proxy - avg_direct
        print(f"\n[+] Performance Overhead Analysis:")
        print(f"  * Average latency overhead added by proxy: [bold yellow]{overhead:.2f} ms[/]")
        print(f"  * Proxy throughput efficiency: [bold green]{(proxy_rps / direct_rps) * 100.0:.1f}%[/] of direct speed")


if __name__ == "__main__":
    try:
        # Use rich console print support if available, fallback otherwise
        try:
            from rich import print
        except ImportError:
            pass
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nBenchmark cancelled.")
