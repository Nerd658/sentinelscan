# SentinelScan Architecture Documentation

## 1. Overview

SentinelScan is an open-source External Attack Surface Management (EASM) engine written in Go. Inspired by Shodan, SentinelScan systematically discovers exposed services, extracts network metadata, correlates domain/IP/certificate identities, tracks temporal changes (first seen / last seen), and evaluates potential origin server exposures behind CDNs and reverse proxies.

---

## 2. High-Level System Architecture

```text
                                 ┌─────────────────────────┐
                                 │     REST API (Go)       │
                                 │     cmd/api             │
                                 └────────────┬────────────┘
                                              │
                                              ▼
                                 ┌─────────────────────────┐
                                 │    Job Queue (Redis)    │
                                 └────────────┬────────────┘
                                              │
               ┌──────────────────────────────┼──────────────────────────────┐
               │                              │                              │
               ▼                              ▼                              ▼
      ┌─────────────────┐            ┌─────────────────┐            ┌─────────────────┐
      │  DNS Workers    │            │   TCP Workers   │            │ Protocol Workers│
      │  (internal/dns) │            │  (internal/tcp) │            │ (HTTP/TLS)      │
      └────────┬────────┘            └────────┬────────┘            └────────┬────────┘
               │                              │                              │
               └──────────────────────────────┼──────────────────────────────┘
                                              │
                                              ▼
                                 ┌─────────────────────────┐
                                 │   Scope Engine (Go)     │
                                 │   (internal/scope)      │
                                 └────────────┬────────────┘
                                              │
                                              ▼
                                 ┌─────────────────────────┐
                                 │  Fingerprint Engine     │
                                 │  (internal/fingerprint) │
                                 └────────────┬────────────┘
                                              │
                                              ▼
                                 ┌─────────────────────────┐
                                 │   Correlation Engine    │
                                 │  (internal/correlation) │
                                 └────────────┬────────────┘
                                              │
                                ┌─────────────┴─────────────┐
                                ▼                           ▼
                      ┌──────────────────┐        ┌──────────────────┐
                      │    PostgreSQL    │        │    OpenSearch    │
                      │  (Relational)    │        │  (Full-Text)     │
                      └──────────────────┘        └──────────────────┘
```

---

## 3. Core Subsystems

### 3.1 Scope Engine (`internal/scope/`)
Safety-by-design component that validates every domain, IP, or CIDR target before issuing any network probes.
- **Rules**: Supports allowed IPs, allowed CIDRs, exact domain matches, and wildcard domain patterns (`*.domain.tld`).
- **Emergency Kill Switch**: Atomic thread-safe toggle to halt all active scanning instantly.
- **Rate Limiter**: Token-bucket algorithm (`golang.org/x/time/rate`) enforcing RPS constraints.
- **Audit Logger**: Appends structured logs of allowed/blocked authorization events.

### 3.2 Storage Layer (`internal/storage/`)
- **PostgreSQL**: Stores relational models (`targets`, `target_scopes`, `hosts`, `ports`, `services`, `certificates`, `http_observations`, `findings`, `correlations`, `scan_jobs`).
- **Redis**: Provides fast queueing for scan job dispatches and state caching.

### 3.3 Search Layer (`internal/search/`)
- **OpenSearch**: Full-text and structured indexing engine enabling fast Shodan-style queries (`ssl.cert.subject.cn:"jobsira.com"`, `port:443`, `http.server:"nginx"`).

### 3.4 API Layer (`cmd/api`, `internal/api`)
- Chi REST API exposing endpoints for targets, scans, hosts, certificates, findings, and search queries.

### 3.5 Scanner Daemon (`cmd/scanner`, `internal/scanner`)
- Goroutine worker pool controller processing tasks contextually with rate limits and scope verification.

---

## 4. Database Schema Overview

Refer to `migrations/000001_init_schema.up.sql` for full DDL definitions.
Key tables:
- `targets` & `target_scopes`: Define authorization scopes.
- `hosts`: IP address inventory with ASN and geolocation metadata.
- `ports` & `services`: Discovered TCP ports and protocol identification.
- `certificates` & `certificate_observations`: Extracted X.509 certs and IP mapping.
- `http_observations`: HTTP headers, status code, title, server banner, and favicon hash.
- `technologies` & `technology_observations`: Detected stack fingerprinting.
- `correlations`: Bi-directional link graph (`IP ↔ Cert`, `Cert ↔ Domain`).
- `findings`: EASM evidence findings (e.g. Potential Origin Exposure).

---

## 5. Security & Compliance Standards

- **No Exploitation**: SentinelScan ONLY conducts asset discovery, metadata collection, banner grabbing, and identity correlation.
- **Scope Verification**: Every network interaction is gated by `IsAllowedTarget()`.
- **Credential Protection**: No hardcoded production credentials; environment variables and structured config are mandatory.
