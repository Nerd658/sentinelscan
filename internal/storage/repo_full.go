package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"sentinelscan/internal/correlation"
	"sentinelscan/internal/http"
	"sentinelscan/internal/scoring"
	"sentinelscan/internal/tcp"
	"sentinelscan/internal/tls"
)

func (p *PostgresDB) SaveHost(ctx context.Context, ip, asn, asnOrg, country, city string) error {
	id := uuid.New().String()
	now := time.Now()

	_, err := p.DB.ExecContext(ctx, `
		INSERT INTO hosts (id, ip, asn, asn_org, country_code, city, first_seen, last_seen)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (ip) DO UPDATE
		SET last_seen = EXCLUDED.last_seen,
		    asn = COALESCE(EXCLUDED.asn, hosts.asn),
		    asn_org = COALESCE(EXCLUDED.asn_org, hosts.asn_org),
		    country_code = COALESCE(EXCLUDED.country_code, hosts.country_code),
		    city = COALESCE(EXCLUDED.city, hosts.city)
	`, id, ip, asn, asnOrg, country, city, now, now)

	if err != nil {
		return fmt.Errorf("failed to save host %s: %w", ip, err)
	}
	return nil
}

func (p *PostgresDB) SavePort(ctx context.Context, portRes tcp.PortResult) error {
	if err := p.SaveHost(ctx, portRes.IP, "", "", "", ""); err != nil {
		return err
	}

	id := uuid.New().String()
	now := time.Now()

	_, err := p.DB.ExecContext(ctx, `
		INSERT INTO ports (id, host_id, port, protocol, state, latency_ms, first_seen, last_seen)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (host_id, port, protocol) DO UPDATE
		SET state = EXCLUDED.state,
		    latency_ms = EXCLUDED.latency_ms,
		    last_seen = EXCLUDED.last_seen
	`, id, portRes.IP, portRes.Port, portRes.Protocol, string(portRes.State), portRes.LatencyMs, now, now)

	if err != nil {
		return fmt.Errorf("failed to save port %s:%d: %w", portRes.IP, portRes.Port, err)
	}
	return nil
}

func (p *PostgresDB) SaveHTTPObservation(ctx context.Context, obs *http.HTTPObservation) error {
	if obs == nil {
		return nil
	}

	id := uuid.New().String()
	now := time.Now()

	headersJSON, _ := json.Marshal(obs.Headers)

	_, err := p.DB.ExecContext(ctx, `
		INSERT INTO http_observations (id, ip, port, host_header, status_code, server_header, location_header, title, favicon_hash, headers, body_size, first_seen, last_seen)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`, id, obs.IP, obs.Port, obs.HostHeader, obs.StatusCode, obs.ServerHeader, obs.Location, obs.Title, obs.FaviconHash, headersJSON, obs.BodySize, now, now)

	if err != nil {
		return fmt.Errorf("failed to save HTTP observation for %s:%d: %w", obs.IP, obs.Port, err)
	}
	return nil
}

func (p *PostgresDB) SaveCertificate(ctx context.Context, obs *tls.TLSObservation) error {
	if obs == nil || obs.FingerprintSHA256 == "" {
		return nil
	}

	id := uuid.New().String()
	now := time.Now()
	sanJSON, _ := json.Marshal(obs.SAN)

	_, err := p.DB.ExecContext(ctx, `
		INSERT INTO certificates (id, fingerprint_sha256, subject_cn, issuer, san, serial_number, valid_from, valid_until, signature_algorithm, public_key_algorithm, first_seen, last_seen)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		ON CONFLICT (fingerprint_sha256) DO UPDATE
		SET last_seen = EXCLUDED.last_seen
	`, id, obs.FingerprintSHA256, obs.SubjectCN, obs.Issuer, sanJSON, obs.SerialNumber, obs.ValidFrom, obs.ValidUntil, obs.SignatureAlgorithm, obs.PublicKeyAlgorithm, now, now)

	if err != nil {
		return fmt.Errorf("failed to save certificate %s: %w", obs.FingerprintSHA256, err)
	}

	// Save observation link
	obsID := uuid.New().String()
	_, _ = p.DB.ExecContext(ctx, `
		INSERT INTO certificate_observations (id, certificate_id, ip, port, sni, first_seen, last_seen)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (certificate_id, ip, port, sni) DO UPDATE
		SET last_seen = EXCLUDED.last_seen
	`, obsID, id, obs.IP, obs.Port, obs.SNI, now, now)

	return nil
}

func (p *PostgresDB) SaveCorrelation(ctx context.Context, link correlation.CorrelationLink) error {
	id := uuid.New().String()
	now := time.Now()

	_, err := p.DB.ExecContext(ctx, `
		INSERT INTO correlations (id, source_type, source_id, relationship, target_type, target_id, confidence, first_seen, last_seen)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, id, link.SourceType, link.SourceID, string(link.Relationship), link.TargetType, link.TargetID, link.Confidence, now, now)

	if err != nil {
		return fmt.Errorf("failed to save correlation link: %w", err)
	}
	return nil
}

func (p *PostgresDB) SaveFinding(ctx context.Context, f scoring.OriginCandidateResult) error {
	id := uuid.New().String()
	now := time.Now()

	evidenceJSON, _ := json.Marshal(f.Evidence)

	_, err := p.DB.ExecContext(ctx, `
		INSERT INTO findings (id, title, finding_type, severity, confidence, target_domain, candidate_ip, score, evidence, first_seen, last_seen)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`, id, "Potential Origin Exposure", "origin_exposure", "high", string(f.Confidence), f.Domain, f.CandidateIP, f.Score, evidenceJSON, now, now)

	if err != nil {
		return fmt.Errorf("failed to save finding for domain %s: %w", f.Domain, err)
	}
	return nil
}
