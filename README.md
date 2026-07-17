# NetGuardian — High-Performance Infrastructure Proxy

> A secure, transparent gateway for network traffic that inspects data at the protocol level while ensuring system scalability.

---

## Features

| Feature | Description |
|---|---|
| **HTTP/HTTPS Proxy** | Forward proxy supporting plain HTTP and HTTPS `CONNECT` tunneling |
| **TLS Termination** | Dynamic certificate generation via a local Root CA for deep HTTPS inspection |
| **IDS/IPS Engine** | Signature-based intrusion detection with 18+ rules across SQL injection, XSS, path traversal, command injection, and reconnaissance |
| **IP Filtering** | Allowlist / blocklist engine supporting individual IPs and CIDR ranges |
| **Rate Limiting** | Token-bucket rate limiter per source IP to prevent abuse |
| **Proxy Authentication** | Optional HTTP Basic authentication for proxy access |
| **Async I/O** | Built on Python `asyncio` for non-blocking, high-concurrency performance |
| **Structured Telemetry** | JSON logging, real-time metrics, Rich console dashboard, and packet hex-dump debugging |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                       NetGuardian Proxy                         │
│                                                                 │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌─────────────┐  │
│  │ IP Filter│──▶│Rate Limit│──▶│   Auth   │──▶│  IDS / IPS  │  │
│  └──────────┘   └──────────┘   └──────────┘   │   Engine    │  │
│                                                └──────┬──────┘  │
│                                                       │         │
│  ┌──────────┐   ┌──────────────┐   ┌─────────────────▼───────┐ │
│  │ TLS Mgr  │──▶│ HTTP Parser  │──▶│     Proxy Handler       │ │
│  └──────────┘   └──────────────┘   │  (HTTP / CONNECT relay) │ │
│                                     └─────────────────────────┘ │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                  Telemetry Layer                          │   │
│  │  Logger  │  Metrics Collector  │  Stats Exporter  │ Dump │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
netguardian_proxy/
├── config/
│   ├── default.yaml            # Full proxy configuration with defaults
│   └── signatures.yaml         # IDS signature rules database
├── src/netguardian/
│   ├── core/                   # Async proxy server, connection handling, tunneling
│   ├── protocol/               # HTTP parser, DNS resolver
│   ├── security/               # TLS manager, IP filter, rate limiter, auth
│   ├── inspection/             # IDS/IPS engine, signature store, matchers
│   ├── telemetry/              # Logger, metrics, stats exporter, packet dumper
│   ├── utils/                  # Config loader, buffer pool, graceful shutdown
│   ├── cli.py                  # CLI argument parser
│   └── __main__.py             # Entry point
├── tests/
│   ├── unit/                   # Module-level unit tests
│   └── integration/            # End-to-end proxy tests
└── scripts/                    # Traffic generator, benchmark tool
```

---

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Start the proxy (IDS mode — alerts only, no blocking)
python -m netguardian --port 8080 --mode ids

# 3. Send traffic through the proxy
curl -x http://127.0.0.1:8080 http://example.com

# 4. Test IDS detection (should trigger an alert)
curl -x http://127.0.0.1:8080 "http://example.com/search?q=1'+OR+1=1--"
```

---

## Configuration

All settings are in [`config/default.yaml`](config/default.yaml). Key sections:

| Section | What it controls |
|---|---|
| `server` | Host, port, max connections, timeouts |
| `tls` | Certificate directory, CA name, key size |
| `ip_filter` | Allowlist, blocklist, default policy |
| `rate_limiter` | Requests/sec, burst size per IP |
| `auth` | Proxy Basic auth credentials |
| `inspection` | IDS vs IPS mode, signature file path |
| `logging` | Log level, file rotation, JSON format |
| `metrics` | Export interval, console table, JSON export |

---

## Development

```bash
# Install dev dependencies
pip install -r requirements-dev.txt

# Run all unit and integration tests
pytest tests/ -v

# Run with coverage
coverage run -m pytest tests/ && coverage report
```

---

## Benchmarks & Traffic Simulation

NetGuardian comes with utility scripts for testing and benchmarking the proxy.

### Traffic Generator
Simulate concurrent users sending a mix of normal requests and common attack vectors:
```bash
# Run a simulated workload of 5 concurrent clients sending 10 requests each
# Target the running proxy at localhost:8080 routing to a target backend
python scripts/generate_traffic.py --proxy-port 8080 --target-host example.com --target-port 80 --concurrency 5 --requests 10
```

### Performance Benchmarks
Compare latency distributions (average, p50, p95, p99) and requests/sec throughput of direct connections versus connections through the NetGuardian proxy:
```bash
# Run performance test comparing proxy route vs direct route
# Target port must point to an active HTTP server instance
python scripts/benchmark.py --proxy-port 8080 --target-host 127.0.0.1 --target-port 9000 --requests 200 --concurrency 20
```

---

## License

MIT
