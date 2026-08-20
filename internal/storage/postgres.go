package storage

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/lib/pq"
	"sentinelscan/pkg/config"
	"sentinelscan/pkg/logger"
)

type PostgresDB struct {
	DB *sql.DB
}

func NewPostgresDB(cfg config.DatabaseConfig) (*PostgresDB, error) {
	db, err := sql.Open("postgres", cfg.DSN())
	if err != nil {
		return nil, fmt.Errorf("failed to open database connection: %w", err)
	}

	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(15 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping postgres database: %w", err)
	}

	logger.Info("Connected to PostgreSQL database", "dbname", cfg.DBName, "host", cfg.Host)
	postgresDB := &PostgresDB{DB: db}
	_ = postgresDB.InitSchema(ctx)
	return postgresDB, nil
}

func (p *PostgresDB) InitSchema(ctx context.Context) error {
	schemaSQL := `
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
		scope_type VARCHAR(50) NOT NULL,
		value VARCHAR(255) NOT NULL,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
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
		host_id VARCHAR(45) NOT NULL,
		port INT NOT NULL,
		protocol VARCHAR(20) NOT NULL DEFAULT 'tcp',
		state VARCHAR(20) NOT NULL,
		latency_ms INT,
		first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		UNIQUE(host_id, port, protocol)
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

	CREATE TABLE IF NOT EXISTS services (
		id UUID PRIMARY KEY,
		port_id UUID NOT NULL REFERENCES ports(id) ON DELETE CASCADE,
		name VARCHAR(100) NOT NULL,
		banner TEXT,
		version VARCHAR(100),
		first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);

	CREATE TABLE IF NOT EXISTS technologies (
		id UUID PRIMARY KEY,
		name VARCHAR(100) UNIQUE NOT NULL,
		category VARCHAR(100),
		description TEXT
	);

	CREATE TABLE IF NOT EXISTS technology_observations (
		id UUID PRIMARY KEY,
		technology_id UUID NOT NULL REFERENCES technologies(id) ON DELETE CASCADE,
		target_type VARCHAR(50) NOT NULL,
		target_identifier VARCHAR(255) NOT NULL,
		confidence INT NOT NULL DEFAULT 100,
		evidence JSONB,
		first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);

	CREATE TABLE IF NOT EXISTS dns_records (
		id UUID PRIMARY KEY,
		domain VARCHAR(255) NOT NULL,
		record_type VARCHAR(20) NOT NULL,
		value TEXT NOT NULL,
		ttl INT,
		first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);

	CREATE TABLE IF NOT EXISTS scan_jobs (
		id UUID PRIMARY KEY,
		target_id UUID REFERENCES targets(id) ON DELETE SET NULL,
		scan_type VARCHAR(50) NOT NULL,
		status VARCHAR(50) NOT NULL DEFAULT 'pending',
		config JSONB,
		error_message TEXT,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		started_at TIMESTAMPTZ,
		finished_at TIMESTAMPTZ
	);

	CREATE TABLE IF NOT EXISTS scan_observations (
		id UUID PRIMARY KEY,
		scan_job_id UUID NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
		observation_type VARCHAR(50) NOT NULL,
		details JSONB NOT NULL,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);

	CREATE TABLE IF NOT EXISTS correlations (
		id UUID PRIMARY KEY,
		source_type VARCHAR(50) NOT NULL,
		source_id VARCHAR(255) NOT NULL,
		relationship VARCHAR(50) NOT NULL,
		target_type VARCHAR(50) NOT NULL,
		target_id VARCHAR(255) NOT NULL,
		confidence INT NOT NULL DEFAULT 100,
		first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);

	CREATE TABLE IF NOT EXISTS findings (
		id UUID PRIMARY KEY,
		title VARCHAR(255) NOT NULL,
		finding_type VARCHAR(100) NOT NULL,
		severity VARCHAR(50) NOT NULL DEFAULT 'info',
		confidence VARCHAR(50) NOT NULL DEFAULT 'MEDIUM',
		target_domain VARCHAR(255),
		candidate_ip VARCHAR(45),
		score INT NOT NULL DEFAULT 0,
		evidence JSONB,
		first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);
	`
	_, err := p.DB.ExecContext(ctx, schemaSQL)
	if err != nil {
		return fmt.Errorf("failed to init database schema: %w", err)
	}
	return nil
}

func (p *PostgresDB) Close() error {
	if p.DB != nil {
		return p.DB.Close()
	}
	return nil
}
