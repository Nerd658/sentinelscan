package config

import (
	"os"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Server.Port != 8080 {
		t.Errorf("expected default server port 8080, got %d", cfg.Server.Port)
	}
	if cfg.Scanner.Workers != 50 {
		t.Errorf("expected default scanner workers 50, got %d", cfg.Scanner.Workers)
	}
	if cfg.Scanner.Timeout != 5*time.Second {
		t.Errorf("expected default scanner timeout 5s, got %v", cfg.Scanner.Timeout)
	}
}

func TestEnvOverride(t *testing.T) {
	os.Setenv("SERVER_PORT", "9090")
	os.Setenv("DB_HOST", "db.internal")
	os.Setenv("DATABASE_URL", "postgresql://user:pass@host:5432/db")
	defer func() {
		os.Unsetenv("SERVER_PORT")
		os.Unsetenv("DB_HOST")
		os.Unsetenv("DATABASE_URL")
	}()

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Server.Port != 9090 {
		t.Errorf("expected overridden server port 9090, got %d", cfg.Server.Port)
	}
	if cfg.Database.Host != "db.internal" {
		t.Errorf("expected overridden DB host db.internal, got %s", cfg.Database.Host)
	}
	if cfg.Database.DSN() != "postgresql://user:pass@host:5432/db" {
		t.Errorf("expected DSN to match DATABASE_URL, got %s", cfg.Database.DSN())
	}
}
