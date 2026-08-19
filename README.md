# SentinelScan — Open-Source External Attack Surface Management (EASM) Engine

SentinelScan is an enterprise-grade, high-performance External Attack Surface Management (EASM) engine written in Go. Inspired by the core principles of Shodan, SentinelScan systematically discovers exposed Internet assets, extracts protocol banners and TLS X.509 certificate metadata, fingerprints modern technology stacks, builds bi-directional identity correlation graphs, tracks historical infrastructure changes, and evaluates potential origin server exposures behind CDNs and reverse proxies.

---

## Key Capabilities

- **High-Throughput Go Core**: Asynchronous worker pool controller with native context cancellation, rate limiting, and connection pooling.
- **Strict Scope Engine (Safety-by-Design)**: Mandatory validation layer enforcing IP, CIDR, and exact/wildcard domain boundaries before initiating any network interaction. Includes an atomic emergency kill-switch and structured file audit logging.
- **Multi-Protocol Discovery Pipeline**:
  - **DNS Engine**: Queries `A`, `AAAA`, `CNAME`, `MX`, `NS`, and `TXT` records with change tracking (`IP_ADDED`, `IP_REMOVED`, `CNAME_CHANGED`, `NS_CHANGED`).
  - **TCP Port Scanner**: Multi-threaded socket dialer probing standard service ports (`22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 5432, 6379, 8080, 8443`) with millisecond latency measurement.
  - **HTTP/HTTPS Inspection Engine**: Captures status codes, server banners, title extractions, redirect chains, headers, and body size limits with virtual host (`Host` header) support.
  - **TLS Inspector**: SNI-aware handshake extracting X.509 Subject Common Names, SANs, Issuers, serial numbers, validity windows, algorithms, and SHA-256 fingerprints.
- **Technology Stack Fingerprinting**: Declarative engine matching web servers (Nginx, Apache, Caddy, Traefik), frameworks (Next.js, React), CDNs (Cloudflare), CMS (WordPress), and SSL issuers.
- **Bi-Directional Identity Graph**: Generates relationship links (`resolves_to`, `observed_on`, `certificate_contains`, `associated_with`).
- **Origin Server Exposure Intelligence**: Evidence-based scoring engine evaluating candidate origin server IPs behind CDNs (CN match +30, SAN match +25, Host match +20, Redirect match +10, Title match +5, History +10) with confidence levels (`LOW`, `MEDIUM`, `HIGH`, `VERY_HIGH`).
- **Full-Text Search & Indexing**: Abstract OpenSearch & PostgreSQL storage engine providing fast Shodan-style query filters (`ssl.cert.subject.cn:"jobsira.com"`, `port:443`, `http.server:"nginx"`).
- **Certificate Transparency Log Discovery**: Integrates CT log search to discover unlinked subdomains and hostnames.

---

## Architectural Data Flow

```text
                                 jobsira.com
                                      │
                        ┌─────────────┴─────────────┐
                        │                           │
                       DNS                     Certificate
                        │                           │
                        ▼                           ▼
                  Cloudflare IPs               jobsira.com
                                                    │
                                                    ▼
                                          Certificate Correlation
                                                    │
                                                    ▼
                                             164.68.126.101
                                                    │
                                ┌───────────────────┼───────────────────┐
                                │                   │                   │
                                ▼                   ▼                   ▼
                               80                  443                8443
                                │                   │
                              HTTP                HTTPS
                                │                   │
                                ▼                   ▼
                             Nginx               TLS Certificate
                                │                   │
                                └──────────┬────────┘
                                           ▼
                                    Fingerprinting
                                           │
                                           ▼
                                    Technologies
                                           │
                                           ▼
                                   Security Findings
```

---

## Directory Layout

```text
sentinelscan/
├── cmd/
│   ├── api/                  # REST API server entrypoint
│   └── scanner/              # Worker daemon controller entrypoint
├── internal/
│   ├── api/                  # Chi REST router & HTTP handlers
│   ├── correlation/          # Bi-directional identity graph engine
│   ├── ct/                   # Certificate Transparency log discovery client
│   ├── dns/                  # DNS resolver & temporal change tracker
│   ├── fingerprint/          # Stack fingerprinting & technology detection
│   ├── http/                 # HTTP/HTTPS response inspection engine
│   ├── scanner/              # Worker pool controller & full pipeline logic
│   ├── scope/                # Target authorization & safety rate limiter
│   ├── scoring/              # Evidence-based origin exposure evaluator
│   ├── search/               # OpenSearch indexing & query parser
│   ├── storage/              # PostgreSQL relational & Redis queue drivers
│    me/tcp/                  # TCP port scanner engine
│   └── tls/                  # TLS certificate inspector
├── pkg/
│   ├── config/               # YAML/Env configuration loader
│   └── logger/               # Structured slog JSON logger
├── migrations/               # PostgreSQL database DDL migration scripts
├── configs/                  # Service configuration files
├── docs/                     # Comprehensive architecture documentation
├── docker-compose.yml        # Docker Compose orchestration stack
├── Dockerfile.api            # Multi-stage Docker image for API
├── Dockerfile.scanner        # Multi-stage Docker image for Scanner
└── Makefile                  # Build, test, and container management targets
```

---

## REST API Specification

| Endpoint | Method | Description |
|---|---|---|
| `/health` | `GET` | Service health status |
| `/api/targets` | `POST` | Register a new target scope |
| `/api/targets` | `GET` | List all registered target scopes |
| `/api/targets/:id` | `GET` | Fetch specific target details |
| `/api/scans` | `POST` | Trigger a new scan job |
| `/api/scans/:id` | `GET` | Retrieve scan job progress |
| `/api/scans/:id/cancel` | `POST` | Cancel active scan job |
| `/api/hosts` | `GET` | List all discovered host IPs |
| `/api/hosts/:ip` | `GET` | Fetch host details (scope enforced) |
| `/api/dns/:domain` | `GET` | Query DNS record set for domain (scope enforced) |
| `/api/services` | `GET` | List all discovered network services |
| `/api/certificates` | `GET` | View extracted X.509 certificates |
| `/api/findings` | `GET` | View origin exposure security findings |
| `/api/search?q=...` | `GET` | Execute full-text query across index |

---

## Environment Configuration

Copy `.env.example` to `.env` to configure your environment variables:

```bash
DATABASE_URL=postgresql://user:password@host:5432/dbname?sslmode=require
SERVER_PORT=8080
LOG_LEVEL=info
SCANNER_WORKERS=50
```

---

## Getting Started

### 1. Requirements
- Go 1.21+ (Installed at `/usr/local/go/bin/go`)
- Docker & Docker Compose

### 2. Local Build & Test

```bash
# Run unit tests across all packages
make test

# Compile API and Scanner binaries
make build
```

### 3. Docker Compose Stack Execution

```bash
docker compose up -d --build
```

---

## Security & Ethics

SentinelScan is designed exclusively for defensive attack surface management and authorized security auditing. It strictly forbids exploitation, credential spraying, brute force, or payload injection. Scope Engine authorization checks are mandatory prior to any network interaction.
