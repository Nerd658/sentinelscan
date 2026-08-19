package config

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server     ServerConfig     `yaml:"server"`
	Database   DatabaseConfig   `yaml:"database"`
	OpenSearch OpenSearchConfig `yaml:"opensearch"`
	Redis      RedisConfig      `yaml:"redis"`
	Scanner    ScannerConfig    `yaml:"scanner"`
	Scope      ScopeConfig      `yaml:"scope"`
	Logging    LoggingConfig    `yaml:"logging"`
}

type ServerConfig struct {
	Port         int           `yaml:"port"`
	ReadTimeout  time.Duration `yaml:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout"`
}

type DatabaseConfig struct {
	URL          string `yaml:"url"`
	Host         string `yaml:"host"`
	Port         int    `yaml:"port"`
	User         string `yaml:"user"`
	Password     string `yaml:"password"`
	DBName       string `yaml:"dbname"`
	SSLMode      string `yaml:"sslmode"`
	MaxOpenConns int    `yaml:"max_open_conns"`
	MaxIdleConns int    `yaml:"max_idle_conns"`
}

func (d DatabaseConfig) DSN() string {
	if d.URL != "" {
		return d.URL
	}
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		d.Host, d.Port, d.User, d.Password, d.DBName, d.SSLMode)
}

type OpenSearchConfig struct {
	Addresses   []string `yaml:"addresses"`
	Username    string   `yaml:"username"`
	Password    string   `yaml:"password"`
	IndexPrefix string   `yaml:"index_prefix"`
}

type RedisConfig struct {
	Address  string `yaml:"address"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
}

type ScannerConfig struct {
	Workers          int           `yaml:"workers"`
	Timeout          time.Duration `yaml:"timeout"`
	RateLimitRPS     int           `yaml:"rate_limit_rps"`
	MaxBodySizeBytes int64         `yaml:"max_body_size_bytes"`
	MaxRedirects     int           `yaml:"max_redirects"`
}

type ScopeConfig struct {
	AuditLogPath string `yaml:"audit_log_path"`
	Strict       bool   `yaml:"strict"`
}

type LoggingConfig struct {
	Level string `yaml:"level"`
}

func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Port:         8080,
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 15 * time.Second,
		},
		Database: DatabaseConfig{
			Host:         "localhost",
			Port:         5432,
			User:         "sentinel",
			Password:     "sentinel_secret",
			DBName:       "sentinelscan",
			SSLMode:      "disable",
			MaxOpenConns: 25,
			MaxIdleConns: 10,
		},
		OpenSearch: OpenSearchConfig{
			Addresses:   []string{"http://localhost:9200"},
			Username:    "admin",
			Password:    "admin",
			IndexPrefix: "sentinelscan",
		},
		Redis: RedisConfig{
			Address:  "localhost:6379",
			Password: "",
			DB:       0,
		},
		Scanner: ScannerConfig{
			Workers:          50,
			Timeout:          5 * time.Second,
			RateLimitRPS:     100,
			MaxBodySizeBytes: 1048576, // 1MB
			MaxRedirects:     5,
		},
		Scope: ScopeConfig{
			AuditLogPath: "/var/log/sentinelscan/scope_audit.log",
			Strict:       true,
		},
		Logging: LoggingConfig{
			Level: "info",
		},
	}
}

func Load(path string) (*Config, error) {
	_ = loadDotEnv(".env")

	cfg := DefaultConfig()

	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			if !os.IsNotExist(err) {
				return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
			}
		} else {
			if err := yaml.Unmarshal(data, cfg); err != nil {
				return nil, fmt.Errorf("failed to parse yaml config: %w", err)
			}
		}
	}

	overrideWithEnv(cfg)
	return cfg, nil
}

func loadDotEnv(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			if os.Getenv(key) == "" {
				os.Setenv(key, val)
			}
		}
	}
	return scanner.Err()
}

func overrideWithEnv(cfg *Config) {
	if val := os.Getenv("DATABASE_URL"); val != "" {
		cfg.Database.URL = val
	} else if val := os.Getenv("DB_URL"); val != "" {
		cfg.Database.URL = val
	}

	if val := os.Getenv("SERVER_PORT"); val != "" {
		if p, err := strconv.Atoi(val); err == nil {
			cfg.Server.Port = p
		}
	}
	if val := os.Getenv("DB_HOST"); val != "" {
		cfg.Database.Host = val
	}
	if val := os.Getenv("DB_PORT"); val != "" {
		if p, err := strconv.Atoi(val); err == nil {
			cfg.Database.Port = p
		}
	}
	if val := os.Getenv("DB_USER"); val != "" {
		cfg.Database.User = val
	}
	if val := os.Getenv("DB_PASSWORD"); val != "" {
		cfg.Database.Password = val
	}
	if val := os.Getenv("DB_NAME"); val != "" {
		cfg.Database.DBName = val
	}
	if val := os.Getenv("OPENSEARCH_URL"); val != "" {
		cfg.OpenSearch.Addresses = []string{val}
	}
	if val := os.Getenv("REDIS_ADDRESS"); val != "" {
		cfg.Redis.Address = val
	}
	if val := os.Getenv("SCANNER_WORKERS"); val != "" {
		if w, err := strconv.Atoi(val); err == nil {
			cfg.Scanner.Workers = w
		}
	}
	if val := os.Getenv("LOG_LEVEL"); val != "" {
		cfg.Logging.Level = val
	}
}
