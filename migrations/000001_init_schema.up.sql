-- SentinelScan Initial Schema Migration

CREATE TABLE IF NOT EXISTS targets (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS target_scopes (
    id UUID PRIMARY KEY,
    target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    scope_type VARCHAR(50) NOT NULL, -- domain, ip, cidr, asn
    value VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS scan_jobs (
    id UUID PRIMARY KEY,
    target_id UUID REFERENCES targets(id) ON DELETE SET NULL,
    scan_type VARCHAR(50) NOT NULL, -- full, dns, tcp, http, tls
    status VARCHAR(50) NOT NULL DEFAULT 'pending', -- pending, running, completed, failed, cancelled
    config JSONB,
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS hosts (
    id UUID PRIMARY KEY,
    ip VARCHAR(45) UNIQUE NOT NULL,
    asn VARCHAR(50),
    asn_org VARCHAR(255),
    country_code VARCHAR(10),
    city VARCHAR(100),
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ports (
    id UUID PRIMARY KEY,
    host_id UUID NOT NULL REFERENCES hosts(ip) ON DELETE CASCADE, -- referenced by IP string or host ID
    port INT NOT NULL,
    protocol VARCHAR(20) NOT NULL DEFAULT 'tcp',
    state VARCHAR(20) NOT NULL, -- open, closed, filtered
    latency_ms INT,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(host_id, port, protocol)
);

CREATE TABLE IF NOT EXISTS services (
    id UUID PRIMARY KEY,
    port_id UUID NOT NULL REFERENCES ports(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL, -- http, https, ssh, etc.
    banner TEXT,
    version VARCHAR(100),
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS dns_records (
    id UUID PRIMARY KEY,
    domain VARCHAR(255) NOT NULL,
    record_type VARCHAR(20) NOT NULL, -- A, AAAA, CNAME, MX, NS, TXT
    value TEXT NOT NULL,
    ttl INT,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(domain, record_type, value)
);

CREATE TABLE IF NOT EXISTS certificates (
    id UUID PRIMARY KEY,
    fingerprint_sha256 VARCHAR(64) UNIQUE NOT NULL,
    subject_cn VARCHAR(255),
    issuer VARCHAR(255),
    san JSONB,
    serial_number VARCHAR(100),
    valid_from TIMESTAMPTZ,
    valid_until TIMESTAMPTZ,
    signature_algorithm VARCHAR(100),
    public_key_algorithm VARCHAR(100),
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS certificate_observations (
    id UUID PRIMARY KEY,
    certificate_id UUID NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,
    ip VARCHAR(45) NOT NULL,
    port INT NOT NULL DEFAULT 443,
    sni VARCHAR(255),
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(certificate_id, ip, port, sni)
);

CREATE TABLE IF NOT EXISTS http_observations (
    id UUID PRIMARY KEY,
    ip VARCHAR(45) NOT NULL,
    port INT NOT NULL,
    host_header VARCHAR(255),
    status_code INT,
    server_header VARCHAR(255),
    location_header TEXT,
    title TEXT,
    favicon_hash VARCHAR(64),
    headers JSONB,
    body_size INT,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS technologies (
    id UUID PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    category VARCHAR(100), -- Web Server, CDN, Framework, CMS
    description TEXT
);

CREATE TABLE IF NOT EXISTS technology_observations (
    id UUID PRIMARY KEY,
    technology_id UUID NOT NULL REFERENCES technologies(id) ON DELETE CASCADE,
    target_type VARCHAR(50) NOT NULL, -- host, domain, service
    target_identifier VARCHAR(255) NOT NULL,
    confidence INT NOT NULL DEFAULT 100,
    evidence JSONB,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS correlations (
    id UUID PRIMARY KEY,
    source_type VARCHAR(50) NOT NULL,
    source_id VARCHAR(255) NOT NULL,
    relationship VARCHAR(50) NOT NULL, -- resolves_to, associated_with, certificate_contains, etc.
    target_type VARCHAR(50) NOT NULL,
    target_id VARCHAR(255) NOT NULL,
    confidence INT NOT NULL DEFAULT 100,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS findings (
    id UUID PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    finding_type VARCHAR(100) NOT NULL, -- origin_exposure, certificate_expired, etc.
    severity VARCHAR(50) NOT NULL DEFAULT 'info', -- info, low, medium, high, critical
    confidence VARCHAR(50) NOT NULL DEFAULT 'MEDIUM', -- LOW, MEDIUM, HIGH, VERY_HIGH
    target_domain VARCHAR(255),
    candidate_ip VARCHAR(45),
    score INT NOT NULL DEFAULT 0,
    evidence JSONB,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS scan_observations (
    id UUID PRIMARY KEY,
    scan_job_id UUID NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    observation_type VARCHAR(50) NOT NULL,
    details JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexing for fast search and correlations
CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip);
CREATE INDEX IF NOT EXISTS idx_ports_host ON ports(host_id, port);
CREATE INDEX IF NOT EXISTS idx_dns_records_domain ON dns_records(domain);
CREATE INDEX IF NOT EXISTS idx_certificates_cn ON certificates(subject_cn);
CREATE INDEX IF NOT EXISTS idx_cert_obs_ip ON certificate_observations(ip);
CREATE INDEX IF NOT EXISTS idx_http_obs_ip_port ON http_observations(ip, port);
CREATE INDEX IF NOT EXISTS idx_findings_domain ON findings(target_domain);
