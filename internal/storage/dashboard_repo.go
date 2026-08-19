package storage

import (
	"context"
	"fmt"
)

type OverviewStats struct {
	TotalTargets      int `json:"total_targets"`
	TotalHosts        int `json:"total_hosts"`
	TotalOpenPorts    int `json:"total_open_ports"`
	TotalServices     int `json:"total_services"`
	TotalCertificates int `json:"total_certificates"`
	TotalTechnologies int `json:"total_technologies"`
	TotalFindings     int `json:"total_findings"`
}

func (p *PostgresDB) GetOverviewStats(ctx context.Context) (*OverviewStats, error) {
	stats := &OverviewStats{}

	row := p.DB.QueryRowContext(ctx, `
		SELECT 
			(SELECT COUNT(*) FROM targets) AS total_targets,
			(SELECT COUNT(*) FROM hosts) AS total_hosts,
			(SELECT COUNT(*) FROM ports WHERE state = 'open') AS total_open_ports,
			(SELECT COUNT(*) FROM services) AS total_services,
			(SELECT COUNT(*) FROM certificates) AS total_certificates,
			(SELECT COUNT(*) FROM technologies) AS total_technologies,
			(SELECT COUNT(*) FROM findings) AS total_findings
	`)

	err := row.Scan(
		&stats.TotalTargets,
		&stats.TotalHosts,
		&stats.TotalOpenPorts,
		&stats.TotalServices,
		&stats.TotalCertificates,
		&stats.TotalTechnologies,
		&stats.TotalFindings,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch overview stats: %w", err)
	}

	return stats, nil
}
