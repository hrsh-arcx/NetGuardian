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

# Run unit tests
pytest tests/unit/ -v

# Run integration tests
pytest tests/integration/ -v

# Run with coverage
coverage run -m pytest tests/ && coverage report
```

---

## License

MIT
