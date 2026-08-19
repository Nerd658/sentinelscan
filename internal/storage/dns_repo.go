package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"sentinelscan/internal/dns"
)

func (p *PostgresDB) UpsertDNSRecords(ctx context.Context, records []dns.DNSRecord) error {
	if len(records) == 0 {
		return nil
	}

	tx, err := p.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO dns_records (id, domain, record_type, value, ttl, first_seen, last_seen)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (domain, record_type, value) DO UPDATE
		SET last_seen = EXCLUDED.last_seen,
		    ttl = EXCLUDED.ttl
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare upsert query: %w", err)
	}
	defer stmt.Close()

	now := time.Now()
	for _, rec := range records {
		id := uuid.New().String()
		firstSeen := rec.FirstSeen
		if firstSeen.IsZero() {
			firstSeen = now
		}

		_, err := stmt.ExecContext(ctx, id, rec.Domain, string(rec.RecordType), rec.Value, rec.TTL, firstSeen, now)
		if err != nil {
			return fmt.Errorf("failed to execute dns upsert for %s: %w", rec.Domain, err)
		}
	}

	return tx.Commit()
}

func (p *PostgresDB) GetDNSRecordsByDomain(ctx context.Context, domain string) ([]dns.DNSRecord, error) {
	rows, err := p.DB.QueryContext(ctx, `
		SELECT domain, record_type, value, ttl, first_seen, last_seen
		FROM dns_records
		WHERE domain = $1
		ORDER BY record_type, value
	`, domain)
	if err != nil {
		return nil, fmt.Errorf("failed to query dns records: %w", err)
	}
	defer rows.Close()

	records := make([]dns.DNSRecord, 0)
	for rows.Next() {
		var rec dns.DNSRecord
		var recordTypeStr string
		if err := rows.Scan(&rec.Domain, &recordTypeStr, &rec.Value, &rec.TTL, &rec.FirstSeen, &rec.LastSeen); err != nil {
			return nil, fmt.Errorf("failed to scan dns row: %w", err)
		}
		rec.RecordType = dns.RecordType(recordTypeStr)
		records = append(records, rec)
	}

	return records, rows.Err()
}
